param([string]$Source, [string]$OutDir)
# Disc images through Windows' IMAPI2 file-system image writer: UDF at each revision, and one
# with ISO 9660 + Joliet + UDF together.
$ErrorActionPreference = "Stop"
Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class StreamSaver {
    public static void Save(object stream, string path) {
        IStream s = (IStream)stream;
        using (FileStream f = File.Create(path)) {
            byte[] buf = new byte[1 << 20];
            IntPtr read = Marshal.AllocHGlobal(4);
            try {
                while (true) {
                    s.Read(buf, buf.Length, read);
                    int n = Marshal.ReadInt32(read);
                    if (n <= 0) break;
                    f.Write(buf, 0, n);
                }
            } finally { Marshal.FreeHGlobal(read); }
        }
    }
}
"@
$jobs = @(
    @{ name = "udf102.iso"; fs = 4; rev = 0x102 },
    @{ name = "udf150.iso"; fs = 4; rev = 0x150 },
    @{ name = "udf200.iso"; fs = 4; rev = 0x200 },
    @{ name = "udf201.iso"; fs = 4; rev = 0x201 },
    @{ name = "udf250.iso"; fs = 4; rev = 0x250 },
    @{ name = "iso_joliet_udf.iso"; fs = 7; rev = 0x102 }
)
foreach ($j in $jobs) {
    $img = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $img.FileSystemsToCreate = $j.fs
    $img.UDFRevision = $j.rev
    $img.VolumeName = "PACKPORT"
    $img.ChooseImageDefaultsForMediaType(13)  # DVD+R: room for the tree
    $img.FileSystemsToCreate = $j.fs
    $img.UDFRevision = $j.rev
    $img.Root.AddTree($Source, $false)
    $result = $img.CreateResultImage()
    [StreamSaver]::Save($result.ImageStream, (Join-Path $OutDir $j.name))
    Write-Output ("{0}: {1} bytes" -f $j.name, (Get-Item (Join-Path $OutDir $j.name)).Length)
}
