from __future__ import annotations

import html as html_lib
import json
import re
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from jinja2 import Environment, FileSystemLoader, select_autoescape


BASE_DIR = Path(__file__).resolve().parent
EXPORT_DIR = BASE_DIR / "exports"
TEMPLATE_DIR = BASE_DIR / "templates"
SAMPLE_DATA_DIR = BASE_DIR / "sample_data"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
COMPONENT_DISPLAY_COLUMNS = [
    "Name",
    "Version",
    "Type",
    "Group",
    "Supplier",
    "PURL",
    "BOM Ref",
    "Licenses",
    "Hashes",
    "Scope",
    "Description",
]
VULNERABILITY_DISPLAY_COLUMNS = [
    "Severity",
    "VulnerabilityID",
    "Package Name",
    "Installed Version",
    "Fixed Version",
    "Title",
    "Primary URL",
]


def na(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else "N/A"
    if isinstance(value, (int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def unique_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = na(value)
        if text == "N/A":
            continue
        if text not in seen:
            seen.add(text)
            result.append(text)
    return result


def load_json_bytes(content: bytes, source_name: str) -> dict[str, Any]:
    if not content:
        raise ValueError(f"{source_name} is empty.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{source_name} is not valid UTF-8 JSON.") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"JSON format error in {source_name}: line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(f"{source_name} must contain a JSON object.")
    return data


def list_sample_json_files(kind: str) -> list[Path]:
    if not SAMPLE_DATA_DIR.exists():
        return []
    files = sorted(SAMPLE_DATA_DIR.glob("*.json"))
    if kind == "trivy":
        return [
            path
            for path in files
            if "trivy" in path.name.lower()
            or "vulnerab" in path.name.lower()
            or "scan" in path.name.lower()
        ]
    return [
        path
        for path in files
        if "trivy" not in path.name.lower()
        and "vulnerab" not in path.name.lower()
        and "scan" not in path.name.lower()
    ]


def load_input_json(uploaded_file: Any, selected_sample: str, sample_files: list[Path]) -> tuple[dict[str, Any] | None, str]:
    if uploaded_file is not None:
        return load_json_bytes(uploaded_file.getvalue(), uploaded_file.name), uploaded_file.name
    if selected_sample:
        path = next((item for item in sample_files if item.name == selected_sample), None)
        if path is None:
            raise ValueError(f"Sample file not found: {selected_sample}")
        return load_json_bytes(path.read_bytes(), path.name), path.name
    return None, ""


def extract_license_labels(licenses: Any) -> list[str]:
    labels: list[str] = []
    if not isinstance(licenses, list):
        return labels

    for item in licenses:
        if isinstance(item, str):
            labels.append(item)
            continue
        if not isinstance(item, dict):
            continue

        expression = item.get("expression")
        if expression:
            labels.append(na(expression))
            continue

        license_value = item.get("license")
        if isinstance(license_value, dict):
            license_id = na(license_value.get("id"))
            license_name = na(license_value.get("name"))
            if license_id != "N/A":
                labels.append(license_id)
            elif license_name != "N/A":
                labels.append(license_name)
        elif isinstance(license_value, str):
            labels.append(license_value)

    return unique_preserve_order(labels)


def format_licenses(licenses: Any) -> str:
    labels = extract_license_labels(licenses)
    return ", ".join(labels) if labels else "N/A"


def format_hashes(hashes: Any) -> str:
    if not isinstance(hashes, list) or not hashes:
        return "N/A"
    values: list[str] = []
    for item in hashes:
        if not isinstance(item, dict):
            continue
        alg = na(item.get("alg"))
        content = na(item.get("content"))
        if content != "N/A":
            values.append(f"{alg}: {content}")
    return "; ".join(values) if values else "N/A"


def format_supplier(supplier: Any) -> str:
    if isinstance(supplier, dict):
        return na(supplier.get("name") or supplier.get("url"))
    return na(supplier)


def component_to_record(component: dict[str, Any], index: int) -> dict[str, Any]:
    bom_ref = na(component.get("bom-ref"))
    effective_ref = bom_ref if bom_ref != "N/A" else f"__missing_bom_ref_{index}"
    licenses = extract_license_labels(component.get("licenses"))
    return {
        "Name": na(component.get("name")),
        "Version": na(component.get("version")),
        "Type": na(component.get("type")),
        "Group": na(component.get("group")),
        "Supplier": format_supplier(component.get("supplier")),
        "PURL": na(component.get("purl")),
        "BOM Ref": bom_ref,
        "Licenses": ", ".join(licenses) if licenses else "N/A",
        "Hashes": format_hashes(component.get("hashes")),
        "Scope": na(component.get("scope")),
        "Description": na(component.get("description")),
        "_effective_bom_ref": effective_ref,
        "_license_list": licenses,
        "_raw": component,
    }


def classify_sbom_scope(file_name: str, metadata: dict[str, Any]) -> dict[str, str]:
    chunks: list[str] = [file_name]
    component = metadata.get("component")
    if isinstance(component, dict):
        chunks.extend([na(component.get("name")), na(component.get("version")), na(component.get("type"))])
        properties = component.get("properties")
        if isinstance(properties, list):
            for item in properties:
                if isinstance(item, dict):
                    chunks.extend([na(item.get("name")), na(item.get("value"))])

    raw_text = " ".join(chunks).lower()
    normalized_text = raw_text.replace("_", " ").replace("-", " ")

    if (
        "testsample" in raw_text
        or "test sample" in normalized_text
        or "test only" in normalized_text
        or "sample/demo/test" in raw_text
    ):
        return {
            "label": "Test Sample SBOM",
            "note": "Not product runtime dependency unless explicitly integrated by user",
        }
    if "product" in normalized_text or "runtime scope" in normalized_text:
        return {
            "label": "Product SBOM",
            "note": "Primary SBOM for product vulnerability assessment",
        }
    return {
        "label": "Unclassified SBOM",
        "note": "Review SBOM metadata and file naming before using it for product vulnerability assessment",
    }


def make_component_dataframe(records: list[dict[str, Any]]) -> pd.DataFrame:
    columns = COMPONENT_DISPLAY_COLUMNS + ["_effective_bom_ref", "_license_list", "_raw"]
    df = pd.DataFrame(records)
    for column in columns:
        if column not in df.columns:
            df[column] = [] if column == "_license_list" else "N/A"
    return df[columns]


def build_license_summary(records: list[dict[str, Any]]) -> pd.DataFrame:
    usage: dict[str, set[str]] = {}
    for record in records:
        labels = record.get("_license_list") or ["N/A"]
        component_name = record.get("Name", "N/A")
        for label in labels:
            usage.setdefault(label, set()).add(component_name)

    rows = [
        {
            "License ID / Name": license_label,
            "Used by component count": len(component_names),
            "Component list": ", ".join(sorted(component_names)),
        }
        for license_label, component_names in sorted(usage.items(), key=lambda item: item[0])
    ]
    return pd.DataFrame(rows, columns=["License ID / Name", "Used by component count", "Component list"])


def build_component_lookup(
    component_records: list[dict[str, Any]],
    metadata_component: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    lookup: dict[str, dict[str, Any]] = {}
    metadata_ref = na(metadata_component.get("bom-ref"))
    if metadata_ref != "N/A":
        lookup[metadata_ref] = {
            "Name": na(metadata_component.get("name")),
            "Version": na(metadata_component.get("version")),
            "Type": na(metadata_component.get("type")),
            "BOM Ref": metadata_ref,
        }

    for record in component_records:
        bom_ref = record.get("BOM Ref", "N/A")
        if bom_ref != "N/A":
            lookup[bom_ref] = record
    return lookup


def build_dependency_graph(dependencies: Any) -> nx.DiGraph:
    graph = nx.DiGraph()
    if not isinstance(dependencies, list):
        return graph

    for dependency in dependencies:
        if not isinstance(dependency, dict):
            continue
        ref = dependency.get("ref")
        if not ref:
            continue
        ref_text = str(ref)
        graph.add_node(ref_text)
        depends_on = dependency.get("dependsOn", [])
        if isinstance(depends_on, str):
            depends_on = [depends_on]
        if not isinstance(depends_on, list):
            continue
        for child in depends_on:
            if child:
                graph.add_edge(ref_text, str(child))
    return graph


def parse_cyclonedx_sbom(data: dict[str, Any], file_name: str) -> dict[str, Any]:
    """Parse a CycloneDX JSON SBOM into dashboard-friendly tables and graph data."""
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("This file is not a CycloneDX JSON SBOM. Expected bomFormat: CycloneDX.")

    warnings: list[str] = []
    metadata = data.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        warnings.append("metadata field is missing or invalid.")

    metadata_component = metadata.get("component")
    if not isinstance(metadata_component, dict):
        metadata_component = {}
        warnings.append("metadata.component field is missing or invalid.")

    components = data.get("components")
    if components is None:
        raise ValueError("CycloneDX SBOM is missing required components[] field.")
    if not isinstance(components, list):
        raise ValueError("CycloneDX components[] field must be an array.")

    dependencies = data.get("dependencies", [])
    if "dependencies" not in data:
        warnings.append("dependencies[] field is missing. Dependency graph will be empty.")
        dependencies = []
    elif not isinstance(dependencies, list):
        warnings.append("dependencies[] field is not an array. Dependency graph will be empty.")
        dependencies = []

    component_records = [
        component_to_record(component, index)
        for index, component in enumerate(components)
        if isinstance(component, dict)
    ]
    skipped_components = len(components) - len(component_records)
    if skipped_components:
        warnings.append(f"{skipped_components} component entries were skipped because they are not JSON objects.")

    components_df = make_component_dataframe(component_records)
    license_df = build_license_summary(component_records)
    graph = build_dependency_graph(dependencies)
    component_lookup = build_component_lookup(component_records, metadata_component)
    unique_licenses = {
        label
        for record in component_records
        for label in (record.get("_license_list") or [])
        if label != "N/A"
    }

    return {
        "file_name": file_name,
        "bom_format": na(data.get("bomFormat")),
        "spec_version": na(data.get("specVersion")),
        "product_name": na(metadata_component.get("name")),
        "product_version": na(metadata_component.get("version")),
        "metadata_component": metadata_component,
        "components_df": components_df,
        "license_df": license_df,
        "dependency_graph": graph,
        "dependency_count": graph.number_of_edges(),
        "total_components": len(component_records),
        "total_licenses": len(unique_licenses),
        "component_lookup": component_lookup,
        "scope": classify_sbom_scope(file_name, metadata),
        "warnings": warnings,
    }


def normalize_severity(value: Any) -> str:
    severity = na(value).upper()
    return severity if severity in SEVERITY_ORDER else "UNKNOWN"


def stringify_list(value: Any) -> str:
    if isinstance(value, list):
        values = [na(item) for item in value if na(item) != "N/A"]
        return "\n".join(values) if values else "N/A"
    return na(value)


def vulnerability_to_record(
    vulnerability: dict[str, Any],
    result: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    return {
        "Severity": normalize_severity(vulnerability.get("Severity")),
        "VulnerabilityID": na(vulnerability.get("VulnerabilityID")),
        "Package Name": na(vulnerability.get("PkgName")),
        "Installed Version": na(vulnerability.get("InstalledVersion")),
        "Fixed Version": stringify_list(vulnerability.get("FixedVersion")),
        "Title": na(vulnerability.get("Title")),
        "Primary URL": na(vulnerability.get("PrimaryURL")),
        "Description": na(vulnerability.get("Description")),
        "CVSS": vulnerability.get("CVSS") or {},
        "References": vulnerability.get("References") or [],
        "Status": na(vulnerability.get("Status")),
        "Target": na(result.get("Target")),
        "Type": na(result.get("Type")),
        "Matched Component": "N/A",
        "Mapped BOM Ref": "N/A",
        "Match Status": "Unmapped",
        "_raw": vulnerability,
        "_index": index,
    }


def empty_vulnerability_dataframe() -> pd.DataFrame:
    columns = (
        VULNERABILITY_DISPLAY_COLUMNS
        + [
            "Description",
            "CVSS",
            "References",
            "Status",
            "Target",
            "Type",
            "Matched Component",
            "Mapped BOM Ref",
            "Match Status",
            "_raw",
            "_index",
        ]
    )
    return pd.DataFrame(columns=columns)


def parse_trivy_json(data: dict[str, Any], file_name: str) -> dict[str, Any]:
    """Parse common Trivy JSON vulnerability result structures."""
    records: list[dict[str, Any]] = []
    results = data.get("Results")
    not_scanned = False

    if isinstance(results, list):
        dash_results = 0
        for result in results:
            if not isinstance(result, dict):
                continue
            target = na(result.get("Target"))
            result_type = na(result.get("Type"))
            if target == "-" and result_type == "-":
                dash_results += 1

            vulnerabilities = result.get("Vulnerabilities") or []
            if isinstance(vulnerabilities, dict):
                vulnerabilities = [vulnerabilities]
            if not isinstance(vulnerabilities, list):
                continue
            for vulnerability in vulnerabilities:
                if isinstance(vulnerability, dict):
                    records.append(vulnerability_to_record(vulnerability, result, len(records)))

        not_scanned = bool(results) and dash_results == len(results) and not records

    top_level_vulnerabilities = data.get("Vulnerabilities")
    if isinstance(top_level_vulnerabilities, dict):
        top_level_vulnerabilities = [top_level_vulnerabilities]
    if isinstance(top_level_vulnerabilities, list):
        result_context = {
            "Target": data.get("Target") or data.get("ArtifactName"),
            "Type": data.get("Type") or data.get("ArtifactType"),
        }
        for vulnerability in top_level_vulnerabilities:
            if isinstance(vulnerability, dict):
                records.append(vulnerability_to_record(vulnerability, result_context, len(records)))

    vulnerability_df = empty_vulnerability_dataframe()
    if records:
        vulnerability_df = pd.DataFrame(records)
        for column in empty_vulnerability_dataframe().columns:
            if column not in vulnerability_df.columns:
                vulnerability_df[column] = "N/A"
        vulnerability_df = vulnerability_df[empty_vulnerability_dataframe().columns]

    return {
        "file_name": file_name,
        "vulnerabilities_df": vulnerability_df,
        "not_scanned": not_scanned,
        "warnings": [],
    }


def lower_text(value: Any) -> str:
    return na(value).lower()


def map_vulnerabilities_to_components(vulnerability_df: pd.DataFrame, components_df: pd.DataFrame) -> pd.DataFrame:
    if vulnerability_df.empty or components_df.empty:
        return vulnerability_df

    mapped_df = vulnerability_df.copy()
    component_records = components_df.to_dict("records")

    for row_index, row in mapped_df.iterrows():
        package_name = lower_text(row.get("Package Name"))
        if package_name == "n/a":
            continue

        match: dict[str, Any] | None = None
        for component in component_records:
            component_name = lower_text(component.get("Name"))
            component_purl = lower_text(component.get("PURL"))
            component_bom_ref = lower_text(component.get("BOM Ref"))
            candidates = [component_name, component_purl, component_bom_ref]
            if package_name in candidates:
                match = component
                break

        if match is None:
            for component in component_records:
                component_name = lower_text(component.get("Name"))
                component_purl = lower_text(component.get("PURL"))
                component_bom_ref = lower_text(component.get("BOM Ref"))
                if (
                    package_name in component_name
                    or package_name in component_purl
                    or package_name in component_bom_ref
                ):
                    match = component
                    break

        if match is not None:
            mapped_df.at[row_index, "Matched Component"] = match.get("Name", "N/A")
            mapped_df.at[row_index, "Mapped BOM Ref"] = match.get("BOM Ref", "N/A")
            mapped_df.at[row_index, "Match Status"] = "Mapped"

    return mapped_df


def vulnerability_summary(vulnerability_df: pd.DataFrame, loaded: bool, not_scanned: bool) -> OrderedDict[str, Any]:
    labels = OrderedDict()
    if not loaded or not_scanned:
        labels["Vulnerability Count"] = "N/A"
        for severity in SEVERITY_ORDER:
            labels[f"{severity.title()} Count"] = "N/A"
        return labels

    counts = vulnerability_df["Severity"].value_counts().to_dict() if not vulnerability_df.empty else {}
    labels["Vulnerability Count"] = int(len(vulnerability_df))
    for severity in SEVERITY_ORDER:
        labels[f"{severity.title()} Count"] = int(counts.get(severity, 0))
    return labels


def component_summary(parsed_sbom: dict[str, Any]) -> OrderedDict[str, Any]:
    return OrderedDict(
        [
            ("Total Components", parsed_sbom["total_components"]),
            ("Total Dependencies", parsed_sbom["dependency_count"]),
            ("Total Licenses", parsed_sbom["total_licenses"]),
        ]
    )


def render_metric_grid(metrics: OrderedDict[str, Any]) -> None:
    items = list(metrics.items())
    for offset in range(0, len(items), 4):
        columns = st.columns(4)
        for column, (label, value) in zip(columns, items[offset : offset + 4]):
            column.metric(label, value)


def render_scope_notice(scope: dict[str, str]) -> None:
    text = f"{scope['label']} - {scope['note']}"
    if scope["label"] == "Product SBOM":
        st.success(text)
    elif scope["label"] == "Test Sample SBOM":
        st.warning(text)
    else:
        st.info(text)


def make_overview_metrics(
    parsed_sbom: dict[str, Any],
    vulnerability_df: pd.DataFrame,
    trivy_loaded: bool,
    trivy_not_scanned: bool,
) -> OrderedDict[str, Any]:
    metrics = OrderedDict(
        [
            ("Product Name", parsed_sbom["product_name"]),
            ("Product Version", parsed_sbom["product_version"]),
            ("SBOM Format", parsed_sbom["bom_format"]),
            ("CycloneDX Version", parsed_sbom["spec_version"]),
            ("Total Components", parsed_sbom["total_components"]),
            ("Total Dependencies", parsed_sbom["dependency_count"]),
            ("Total Licenses", parsed_sbom["total_licenses"]),
        ]
    )
    metrics.update(vulnerability_summary(vulnerability_df, trivy_loaded, trivy_not_scanned))
    return metrics


def render_overview(
    parsed_sbom: dict[str, Any],
    vulnerability_df: pd.DataFrame,
    trivy_loaded: bool,
    trivy_not_scanned: bool,
) -> None:
    render_scope_notice(parsed_sbom["scope"])
    render_metric_grid(make_overview_metrics(parsed_sbom, vulnerability_df, trivy_loaded, trivy_not_scanned))

    components_df = parsed_sbom["components_df"]
    if not components_df.empty:
        type_counts = components_df["Type"].value_counts().reset_index()
        type_counts.columns = ["Type", "Count"]
        fig = px.bar(type_counts, x="Type", y="Count", title="Component Type Distribution")
        fig.update_layout(height=360, margin=dict(l=10, r=10, t=45, b=10))
        st.plotly_chart(fig, use_container_width=True)

    if trivy_loaded and trivy_not_scanned:
        st.warning("Not scanned != Clean")
    elif trivy_loaded and vulnerability_df.empty:
        st.info("No vulnerabilities found or no mapped vulnerabilities")
    elif not trivy_loaded:
        st.info("No Trivy JSON vulnerability result has been imported.")


def license_matches(record: pd.Series, selected_licenses: list[str]) -> bool:
    if not selected_licenses:
        return True
    labels = record.get("_license_list") or ["N/A"]
    return any(label in selected_licenses for label in labels)


def render_components_tab(parsed_sbom: dict[str, Any], vulnerability_df: pd.DataFrame) -> None:
    components_df = parsed_sbom["components_df"]
    if components_df.empty:
        st.info("No components found in this SBOM.")
        return

    search_text = st.text_input("Search component name / purl / bom-ref", key="component_search")
    type_options = sorted(components_df["Type"].fillna("N/A").unique().tolist())
    selected_types = st.multiselect("Filter by type", type_options, default=[])
    license_options = sorted(
        {
            label
            for labels in components_df["_license_list"].tolist()
            for label in (labels or ["N/A"])
        }
    )
    selected_licenses = st.multiselect("Filter by license", license_options, default=[])

    filtered_df = components_df.copy()
    if search_text.strip():
        query = search_text.strip().lower()
        filtered_df = filtered_df[
            filtered_df.apply(
                lambda row: query
                in " ".join([na(row["Name"]), na(row["PURL"]), na(row["BOM Ref"])]).lower(),
                axis=1,
            )
        ]
    if selected_types:
        filtered_df = filtered_df[filtered_df["Type"].isin(selected_types)]
    if selected_licenses:
        filtered_df = filtered_df[filtered_df.apply(lambda row: license_matches(row, selected_licenses), axis=1)]

    display_df = filtered_df[COMPONENT_DISPLAY_COLUMNS]
    table_event = st.dataframe(
        display_df,
        hide_index=True,
        use_container_width=True,
        selection_mode="single-row",
        on_select="rerun",
        key="component_table",
    )

    selected_row_index = None
    if getattr(table_event, "selection", None) and table_event.selection.rows:
        selected_row_index = table_event.selection.rows[0]

    if selected_row_index is None and not filtered_df.empty:
        option_labels = [
            f"{row['Name']} | {row['Version']} | {row['BOM Ref']}"
            for _, row in filtered_df.iterrows()
        ]
        selected_label = st.selectbox("Select component details", option_labels, key="component_select")
        selected_row_index = option_labels.index(selected_label)

    if selected_row_index is not None and not filtered_df.empty:
        record = filtered_df.iloc[selected_row_index]
        render_component_detail(record, vulnerability_df)


def render_component_detail(record: pd.Series, vulnerability_df: pd.DataFrame) -> None:
    st.subheader(f"Component Detail: {record['Name']}")
    detail_rows = [
        {"Field": column, "Value": record[column]}
        for column in ["Name", "Version", "Type", "Group", "Supplier", "PURL", "BOM Ref", "Licenses", "Hashes", "Scope"]
    ]
    st.table(pd.DataFrame(detail_rows))
    st.markdown("**Description**")
    st.write(record["Description"])

    raw = record.get("_raw") if isinstance(record.get("_raw"), dict) else {}
    with st.expander("External References", expanded=False):
        st.json(raw.get("externalReferences") or [])
    with st.expander("Properties", expanded=False):
        st.json(raw.get("properties") or [])

    related_vulnerabilities = pd.DataFrame()
    if not vulnerability_df.empty:
        name = na(record["Name"])
        bom_ref = na(record["BOM Ref"])
        related_vulnerabilities = vulnerability_df[
            (vulnerability_df["Matched Component"] == name)
            | ((bom_ref != "N/A") & (vulnerability_df["Mapped BOM Ref"] == bom_ref))
            | (vulnerability_df["Package Name"].str.lower() == name.lower())
        ]

    st.markdown("**Related Vulnerabilities**")
    if related_vulnerabilities.empty:
        st.info("No vulnerabilities mapped to this component.")
    else:
        st.dataframe(
            related_vulnerabilities[VULNERABILITY_DISPLAY_COLUMNS + ["Match Status"]],
            hide_index=True,
            use_container_width=True,
        )


def node_label(ref: str, component_lookup: dict[str, dict[str, Any]]) -> str:
    record = component_lookup.get(ref)
    if not record:
        return ref
    label = na(record.get("Name"))
    return label if label != "N/A" else ref


def node_hover(ref: str, component_lookup: dict[str, dict[str, Any]]) -> str:
    record = component_lookup.get(ref, {})
    name = html_lib.escape(node_label(ref, component_lookup))
    bom_ref = html_lib.escape(ref)
    version = html_lib.escape(na(record.get("Version")))
    component_type = html_lib.escape(na(record.get("Type")))
    return f"Name: {name}<br>BOM Ref: {bom_ref}<br>Version: {version}<br>Type: {component_type}"


def dependency_figure(
    graph: nx.DiGraph,
    component_lookup: dict[str, dict[str, Any]],
    root_ref: str | None = None,
) -> go.Figure:
    if graph.number_of_nodes() == 1:
        positions = {next(iter(graph.nodes)): (0.0, 0.0)}
    else:
        positions = nx.spring_layout(graph, seed=42, k=None)

    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for source, target in graph.edges():
        x0, y0 = positions[source]
        x1, y1 = positions[target]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1.2, color="#8a96a8"),
        hoverinfo="none",
        mode="lines",
    )

    node_x: list[float] = []
    node_y: list[float] = []
    node_text: list[str] = []
    hover_text: list[str] = []
    colors: list[str] = []
    for node in graph.nodes():
        x, y = positions[node]
        node_x.append(x)
        node_y.append(y)
        node_text.append(node_label(node, component_lookup))
        hover_text.append(node_hover(node, component_lookup))
        colors.append("#0f766e" if root_ref and node == root_ref else "#2563eb")

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=node_text,
        textposition="top center",
        hovertext=hover_text,
        hoverinfo="text",
        marker=dict(size=16, color=colors, line=dict(width=1, color="#ffffff")),
    )

    figure = go.Figure(data=[edge_trace, node_trace])
    figure.update_layout(
        height=650,
        margin=dict(l=10, r=10, t=20, b=10),
        showlegend=False,
        plot_bgcolor="#ffffff",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    )
    return figure


def render_dependency_tab(parsed_sbom: dict[str, Any]) -> None:
    graph: nx.DiGraph = parsed_sbom["dependency_graph"]
    if graph.number_of_edges() == 0:
        st.info("No dependency relationship found in this SBOM")
        return

    component_lookup = parsed_sbom["component_lookup"]
    node_options = sorted(graph.nodes(), key=lambda ref: node_label(ref, component_lookup).lower())
    labels = {f"{node_label(ref, component_lookup)} | {ref}": ref for ref in node_options}
    root_label = st.selectbox("Root component", list(labels.keys()))
    root_ref = labels[root_label]
    graph_mode = st.radio("Graph scope", ["Direct dependencies", "Full graph"], horizontal=True)

    if graph_mode == "Direct dependencies":
        direct_nodes = [root_ref] + list(graph.successors(root_ref))
        view_graph = graph.subgraph(direct_nodes).copy()
        if view_graph.number_of_edges() == 0:
            st.info("No dependency relationship found in this SBOM")
            return
    else:
        view_graph = graph

    st.plotly_chart(dependency_figure(view_graph, component_lookup, root_ref), use_container_width=True)


def render_license_tab(parsed_sbom: dict[str, Any]) -> None:
    license_df = parsed_sbom["license_df"]
    if license_df.empty:
        st.info("No license information found.")
        return
    st.dataframe(license_df, hide_index=True, use_container_width=True)


def render_vulnerability_tab(trivy_state: dict[str, Any], vulnerability_df: pd.DataFrame) -> None:
    if not trivy_state.get("loaded"):
        st.info("Upload a Trivy JSON vulnerability result to view vulnerability data.")
        return

    if trivy_state.get("not_scanned"):
        st.warning("Not scanned != Clean")

    if vulnerability_df.empty:
        st.info("No vulnerabilities found or no mapped vulnerabilities")
        return

    severity_counts = (
        vulnerability_df["Severity"]
        .value_counts()
        .reindex(SEVERITY_ORDER, fill_value=0)
        .reset_index()
    )
    severity_counts.columns = ["Severity", "Count"]
    fig = px.bar(severity_counts, x="Severity", y="Count", title="Vulnerability Severity Distribution")
    fig.update_layout(height=360, margin=dict(l=10, r=10, t=45, b=10))
    st.plotly_chart(fig, use_container_width=True)

    unmapped_count = int((vulnerability_df["Match Status"] == "Unmapped").sum())
    if unmapped_count:
        st.warning(f"{unmapped_count} Trivy package name(s) could not be mapped to SBOM components.")

    severity_filter = st.multiselect("Filter by severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
    package_options = sorted(vulnerability_df["Package Name"].fillna("N/A").unique().tolist())
    package_filter = st.multiselect("Filter by package/component", package_options, default=[])
    search_text = st.text_input("Search CVE ID / title / package", key="vulnerability_search")

    filtered_df = vulnerability_df.copy()
    if severity_filter:
        filtered_df = filtered_df[filtered_df["Severity"].isin(severity_filter)]
    if package_filter:
        filtered_df = filtered_df[filtered_df["Package Name"].isin(package_filter)]
    if search_text.strip():
        query = search_text.strip().lower()
        filtered_df = filtered_df[
            filtered_df.apply(
                lambda row: query
                in " ".join([na(row["VulnerabilityID"]), na(row["Title"]), na(row["Package Name"])]).lower(),
                axis=1,
            )
        ]

    display_columns = VULNERABILITY_DISPLAY_COLUMNS + ["Matched Component", "Match Status"]
    table_event = st.dataframe(
        filtered_df[display_columns],
        hide_index=True,
        use_container_width=True,
        selection_mode="single-row",
        on_select="rerun",
        key="vulnerability_table",
    )

    selected_row_index = None
    if getattr(table_event, "selection", None) and table_event.selection.rows:
        selected_row_index = table_event.selection.rows[0]

    if selected_row_index is None and not filtered_df.empty:
        labels = [
            f"{row['VulnerabilityID']} | {row['Package Name']} | {row['Severity']}"
            for _, row in filtered_df.iterrows()
        ]
        selected_label = st.selectbox("Select vulnerability details", labels, key="vulnerability_select")
        selected_row_index = labels.index(selected_label)

    if selected_row_index is not None and not filtered_df.empty:
        render_vulnerability_detail(filtered_df.iloc[selected_row_index])


def render_vulnerability_detail(record: pd.Series) -> None:
    st.subheader(f"Vulnerability Detail: {record['VulnerabilityID']}")
    rows = [
        {"Field": "Severity", "Value": record["Severity"]},
        {"Field": "Package Name", "Value": record["Package Name"]},
        {"Field": "Installed Version", "Value": record["Installed Version"]},
        {"Field": "Fixed Version", "Value": record["Fixed Version"]},
        {"Field": "Status", "Value": record["Status"]},
        {"Field": "Primary URL", "Value": record["Primary URL"]},
        {"Field": "Matched Component", "Value": record["Matched Component"]},
        {"Field": "Mapped BOM Ref", "Value": record["Mapped BOM Ref"]},
    ]
    st.table(pd.DataFrame(rows))
    st.markdown("**Title**")
    st.write(record["Title"])
    st.markdown("**Description**")
    st.write(record["Description"])
    with st.expander("CVSS", expanded=True):
        st.json(record["CVSS"] if isinstance(record["CVSS"], dict) else {})
    with st.expander("References", expanded=False):
        references = record["References"] if isinstance(record["References"], list) else []
        if references:
            for reference in references:
                st.write(reference)
        else:
            st.write("N/A")


def safe_report_name(sbom_file_name: str) -> str:
    stem = Path(sbom_file_name or "sbom").stem
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")
    return sanitized or "sbom"


def build_report_interpretation(
    parsed_sbom: dict[str, Any],
    vulnerability_df: pd.DataFrame,
    trivy_loaded: bool,
    trivy_not_scanned: bool,
) -> list[str]:
    scope_label = parsed_sbom["scope"]["label"]
    product_name = parsed_sbom["product_name"]
    product_version = parsed_sbom["product_version"]
    total_components = parsed_sbom["total_components"]
    total_licenses = parsed_sbom["total_licenses"]

    interpretation = [
        (
            f"This report summarizes the loaded CycloneDX SBOM for {product_name} "
            f"{product_version}. It is a human-readable dashboard export, not a replacement "
            "for the original SBOM evidence package."
        ),
        (
            f"The SBOM contains {total_components} component(s) and "
            f"{total_licenses} distinct declared license value(s). Review the component and "
            "license tables when deciding redistribution, reuse, or product integration scope."
        ),
    ]

    if scope_label == "Product SBOM":
        interpretation.append(
            "This SBOM is classified as Product SBOM and should be used as the primary input "
            "for product vulnerability assessment."
        )
    elif scope_label == "Test Sample SBOM":
        interpretation.append(
            "This SBOM is classified as Test Sample SBOM. Its components are not product "
            "runtime dependencies unless they are explicitly reused, redistributed, or "
            "integrated by the user."
        )
    else:
        interpretation.append(
            "The SBOM scope could not be classified automatically. Review the file name, "
            "metadata, and release notes before using it for product vulnerability assessment."
        )

    if not trivy_loaded:
        interpretation.append(
            "No Trivy JSON vulnerability result was loaded for this report. Vulnerability "
            "status is unknown; this must not be interpreted as zero vulnerabilities or clean."
        )
    elif trivy_not_scanned:
        interpretation.append(
            "The vulnerability scan result indicates Not scanned. Not scanned != Clean, so no "
            "vulnerability conclusion can be made from this scan result."
        )
    elif vulnerability_df.empty:
        interpretation.append(
            "A Trivy result was loaded, but no vulnerabilities were found or no vulnerabilities "
            "could be mapped. Confirm that the scanner actually covered and mapped the SBOM "
            "components before treating this as clean."
        )
    else:
        severity_counts = vulnerability_df["Severity"].value_counts().to_dict()
        interpretation.append(
            "A Trivy result was loaded and vulnerabilities are listed in this report: "
            f"{len(vulnerability_df)} total, "
            f"{int(severity_counts.get('CRITICAL', 0))} critical, "
            f"{int(severity_counts.get('HIGH', 0))} high, "
            f"{int(severity_counts.get('MEDIUM', 0))} medium, "
            f"{int(severity_counts.get('LOW', 0))} low, and "
            f"{int(severity_counts.get('UNKNOWN', 0))} unknown."
        )
        if "Match Status" in vulnerability_df.columns:
            unmapped_count = int((vulnerability_df["Match Status"] == "Unmapped").sum())
            if unmapped_count:
                interpretation.append(
                    f"{unmapped_count} vulnerability package name(s) could not be mapped to "
                    "SBOM components. Review package names, PURLs, and bom-ref values before "
                    "making final vulnerability assessment decisions."
                )

    return interpretation


def build_report_context(
    parsed_sbom: dict[str, Any],
    vulnerability_df: pd.DataFrame,
    trivy_loaded: bool,
    trivy_not_scanned: bool,
) -> dict[str, Any]:
    components_df = parsed_sbom["components_df"]
    component_rows = components_df[COMPONENT_DISPLAY_COLUMNS].to_dict("records")
    vulnerability_rows = (
        vulnerability_df[VULNERABILITY_DISPLAY_COLUMNS].to_dict("records")
        if not vulnerability_df.empty
        else []
    )
    license_rows = [
        {
            "license": row["License ID / Name"],
            "count": row["Used by component count"],
            "components": row["Component list"],
        }
        for _, row in parsed_sbom["license_df"].iterrows()
    ]

    return {
        "report_title": "SBOM Dashboard Report",
        "generated_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sbom_file_name": parsed_sbom["file_name"],
        "product_name": parsed_sbom["product_name"],
        "product_version": parsed_sbom["product_version"],
        "sbom_format": parsed_sbom["bom_format"],
        "spec_version": parsed_sbom["spec_version"],
        "scope_label": parsed_sbom["scope"]["label"],
        "scope_note": parsed_sbom["scope"]["note"],
        "interpretation": build_report_interpretation(
            parsed_sbom,
            vulnerability_df,
            trivy_loaded,
            trivy_not_scanned,
        ),
        "component_summary": component_summary(parsed_sbom),
        "vulnerability_summary": vulnerability_summary(vulnerability_df, trivy_loaded, trivy_not_scanned),
        "licenses": license_rows,
        "component_columns": COMPONENT_DISPLAY_COLUMNS,
        "components": component_rows,
        "vulnerability_columns": VULNERABILITY_DISPLAY_COLUMNS,
        "vulnerabilities": vulnerability_rows,
        "notes": [
            "Not scanned != Clean",
            "Test Sample SBOM components are not product runtime dependencies unless explicitly reused, redistributed, or integrated.",
            "Product SBOM should be used for product vulnerability assessment.",
        ],
    }


def export_html_report(
    parsed_sbom: dict[str, Any],
    vulnerability_df: pd.DataFrame,
    trivy_loaded: bool,
    trivy_not_scanned: bool,
) -> Path:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    template = environment.get_template("report.html.j2")
    html = template.render(
        build_report_context(parsed_sbom, vulnerability_df, trivy_loaded, trivy_not_scanned)
    )
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = EXPORT_DIR / f"sbom_report_{safe_report_name(parsed_sbom['file_name'])}_{timestamp}.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path


def sidebar_inputs() -> tuple[dict[str, Any] | None, str, dict[str, Any] | None, str, list[str]]:
    messages: list[str] = []
    st.sidebar.header("Input Files")

    sbom_sample_files = list_sample_json_files("sbom")
    trivy_sample_files = list_sample_json_files("trivy")

    sbom_upload = st.sidebar.file_uploader(
        "Upload CycloneDX JSON SBOM",
        type=["json"],
        key="sbom_upload",
    )
    sbom_sample = ""
    if sbom_sample_files:
        sbom_sample = st.sidebar.selectbox(
            "Or load sample SBOM from sample_data",
            [""] + [path.name for path in sbom_sample_files],
            key="sbom_sample",
        )

    trivy_upload = st.sidebar.file_uploader(
        "Upload Trivy JSON vulnerability result",
        type=["json"],
        key="trivy_upload",
    )
    trivy_sample = ""
    if trivy_sample_files:
        trivy_sample = st.sidebar.selectbox(
            "Or load sample Trivy JSON from sample_data",
            [""] + [path.name for path in trivy_sample_files],
            key="trivy_sample",
        )

    sbom_data: dict[str, Any] | None = None
    sbom_name = ""
    trivy_data: dict[str, Any] | None = None
    trivy_name = ""

    try:
        sbom_data, sbom_name = load_input_json(sbom_upload, sbom_sample, sbom_sample_files)
    except ValueError as exc:
        messages.append(str(exc))

    try:
        trivy_data, trivy_name = load_input_json(trivy_upload, trivy_sample, trivy_sample_files)
    except ValueError as exc:
        messages.append(str(exc))

    return sbom_data, sbom_name, trivy_data, trivy_name, messages


def main() -> None:
    st.set_page_config(page_title="Offline SBOM Dashboard", layout="wide")
    st.title("Offline SBOM Dashboard")
    st.caption("CycloneDX JSON SBOM and Trivy JSON vulnerability scan viewer")

    sbom_data, sbom_name, trivy_data, trivy_name, input_errors = sidebar_inputs()
    for message in input_errors:
        st.error(message)

    parsed_sbom: dict[str, Any] | None = None
    trivy_state: dict[str, Any] = {
        "loaded": False,
        "file_name": "",
        "not_scanned": False,
        "warnings": [],
    }
    vulnerability_df = empty_vulnerability_dataframe()

    if sbom_data is not None:
        try:
            parsed_sbom = parse_cyclonedx_sbom(sbom_data, sbom_name)
        except ValueError as exc:
            st.error(str(exc))

    if trivy_data is not None:
        trivy_state = parse_trivy_json(trivy_data, trivy_name)
        trivy_state["loaded"] = True
        vulnerability_df = trivy_state["vulnerabilities_df"]

    if parsed_sbom is not None and not vulnerability_df.empty:
        vulnerability_df = map_vulnerabilities_to_components(
            vulnerability_df,
            parsed_sbom["components_df"],
        )

    if parsed_sbom is not None:
        if st.sidebar.button("Export HTML Report"):
            report_path = export_html_report(
                parsed_sbom,
                vulnerability_df,
                trivy_state.get("loaded", False),
                trivy_state.get("not_scanned", False),
            )
            st.sidebar.success(f"Exported: {report_path}")
    else:
        st.sidebar.button("Export HTML Report", disabled=True)

    if parsed_sbom is None:
        st.info("Upload a CycloneDX JSON SBOM to start.")
        st.markdown(
            """
Required SBOM fields:

- `bomFormat`: `CycloneDX`
- `specVersion`
- `metadata.component.name`
- `metadata.component.version`
- `components[]`
- `dependencies[]`
"""
        )
        return

    for warning in parsed_sbom["warnings"]:
        st.warning(warning)

    tabs = st.tabs(["Dashboard", "Components", "Dependency Tree", "Licenses", "Vulnerabilities"])
    with tabs[0]:
        render_overview(
            parsed_sbom,
            vulnerability_df,
            trivy_state.get("loaded", False),
            trivy_state.get("not_scanned", False),
        )
    with tabs[1]:
        render_components_tab(parsed_sbom, vulnerability_df)
    with tabs[2]:
        render_dependency_tab(parsed_sbom)
    with tabs[3]:
        render_license_tab(parsed_sbom)
    with tabs[4]:
        render_vulnerability_tab(trivy_state, vulnerability_df)


if __name__ == "__main__":
    main()
