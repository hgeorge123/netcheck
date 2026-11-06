# Opens a .docx in a private Word instance, updates the table of contents and fields, saves it and exports a PDF for review.
# Needs Microsoft Word on Windows: powershell -File finish-docx.ps1 -Files ..\out\<name>.docx
param([string[]]$Files)
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0
$noSave = [ref]0
try {
  foreach ($file in $Files) {
    $full = (Resolve-Path $file).Path
    $doc = $word.Documents.Open($full, $false, $false, $false)
    $doc.Repaginate()
    [void]$doc.Fields.Update()
    # Figure numbers: same look as the "Figura" label next to them (bold, ink colour; Word colours are BGR).
    foreach ($f in $doc.Fields) {
      if ($f.Type -eq 12) {
        $f.Result.Font.Bold = 1
        $f.Result.Font.Color = 0x1F1916
      }
    }
    $doc.TablesOfContents.Item(1).Update()
    $doc.Repaginate()
    $doc.TablesOfContents.Item(1).UpdatePageNumbers()
    $info = "{0}: pages={1} compat={2} tocs={3} tables={4} inline={5} fields={6}" -f (Split-Path $full -Leaf), $doc.ComputeStatistics(2), $doc.CompatibilityMode, $doc.TablesOfContents.Count, $doc.Tables.Count, $doc.InlineShapes.Count, $doc.Fields.Count
    $info
    $doc.Save()
    $pdf = [IO.Path]::ChangeExtension($full, '.word-review.pdf')
    $doc.ExportAsFixedFormat($pdf, 17)
    # This Word build drops the automation connection after exporting; the document is already saved by then.
    try { $doc.Close($noSave) } catch { "Word dropped the connection after exporting (the document is already saved)" }
  }
} finally {
  try { $word.Quit($noSave) } catch {}
  [void][Runtime.InteropServices.Marshal]::ReleaseComObject($word)
}
