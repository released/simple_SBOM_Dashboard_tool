# Sample Data

Place local CycloneDX JSON SBOM files and Trivy JSON scan results in this
directory if you want them to appear in the dashboard sample selectors.

Expected examples:

```text
sample_data/
|-- Product_SBOM.cdx.json
|-- TestSample_SBOM.cdx.json
`-- trivy_Product_SBOM.json
```

The application also supports browser upload, so sample files are optional.

Do not place customer or vendor SBOM files in this directory when packaging the
dashboard for external delivery.
