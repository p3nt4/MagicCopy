function New-CryptographyKey()
{
<#
.SYNOPSIS 
Generates a random cryptography key.

.DESCRIPTION
Generates a random cryptography key based on the desired key size.

.PARAMETER Algorithm
Algorithm to generate key for.

.PARAMETER KeySize
Number of bits the generated key will have.

.PARAMETER AsPlainText
Returns a String instead of SecureString.

.OUTPUTS
System.Security.SecureString. New-CryptographyKey return the key as a SecureString by default.
System.String. New-CryptographyKey will return the key in plain text as a string if the -AsPlainText parameter is specified.

.EXAMPLE
$key = New-CryptographyKey
This example generates a random 256-bit AES key and stores it in the variable $key.

.NOTES
Author: Tyler Siegrist
Date: 9/22/2017
#>
[CmdletBinding()]
[OutputType([System.Security.SecureString])]
[OutputType([String], ParameterSetName='PlainText')]
Param(
    [Parameter(Mandatory=$false, Position=1)]
    [ValidateSet('AES','DES','RC2','Rijndael','TripleDES')]
    [String]$Algorithm='AES',
    [Parameter(Mandatory=$false, Position=2)]
    [Int]$KeySize,
    [Parameter(ParameterSetName='PlainText')]
    [Switch]$AsPlainText
)
    Process
    {
        try
        {
            $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create($Algorithm)
            if($PSBoundParameters.ContainsKey('KeySize')){
                $Crypto.KeySize = $KeySize
            }
            $Crypto.GenerateKey()
            if($AsPlainText)
            {
                return [System.Convert]::ToBase64String($Crypto.Key)
            }
            else
            {
                return [System.Convert]::ToBase64String($Crypto.Key) | ConvertTo-SecureString -AsPlainText -Force
            }
        }
        catch
        {
            Write-Error $_
        }
        
    }
}

Function Magic-Put([STRING] $File, [STRING] $Destination, [int] $PieceSize = 10MB, [STRING] $Key, [int] $FirstPiece = 1, [int] $LastPiece = 10MB, [int] $Threads = 1){
    [ScriptBlock] $ScriptBlock = {
        param([Byte[]]$BUFFER,[String]$path,[String]$Key,[int]$BYTESREAD)
        try{
            $Key2 = $Key | ConvertTo-SecureString -AsPlainText -Force;
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key2)
            $EncryptionKey = [System.Convert]::FromBase64String([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))
            $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create('AES')
            $Crypto.KeySize = $EncryptionKey.Length*8
            $Crypto.Key = $EncryptionKey
            $FileStreamWriter = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Create);
            $Crypto.GenerateIV()
            $FileStreamWriter.Write([System.BitConverter]::GetBytes($Crypto.IV.Length), 0, 4);
            $Transform = $Crypto.CreateEncryptor();
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write);    
            $CryptoStream.Write($BUFFER, 0, $BYTESREAD);
            $CryptoStream.FlushFinalBlock();
        }Finally{
            if($FileStreamWriter){$FileStreamWriter.Close()};
            if($CryptoStream){$CryptoStream.Close()};
        }
    }
    try{
        $ErrorActionPreference = "Stop"
        "Source: $File";
        "Destination: $Destination";
        "Split Size: $PieceSize";
        "Threads: $Threads";
        $FileStreamReader = New-Object System.IO.FileStream($File, [System.IO.FileMode]::Open)
	    $FILEPATH = [IO.Path]::GetFullPath($Destination);
	    if ($FILEPATH -ne "") { $FILEPATH = $FILEPATH + "\";}
	    $FILENAME = [IO.Path]::GetFileNameWithoutExtension($File);
	    $EXTENSION  = [IO.Path]::GetExtension($File);
	    [Byte[]]$BUFFER = New-Object Byte[] $PieceSize;
	    [int]$BYTESREAD = 0;
	    $NUMFILE = $FirstPiece;
        $FileStreamReader.Position = ($PieceSize * ($FirstPiece - 1));
	    while (($BYTESREAD = $FileStreamReader.Read($BUFFER, 0, $BUFFER.Length)) -gt 0){
            if($NUMFILE -eq $LastPiece + 1){
                break;
            }
		    "[$NUMFILE] Reading $BYTESREAD bytes of $File";
		    $NEWNAME = "{0}{1}{3}{2,2:00}.AES" -f ($FILEPATH, $FILENAME, $NUMFILE, $EXTENSION);
            if($Threads -eq 1){
                Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $BUFFER,$NEWNAME,$Key,$BYTESREAD;
            }
            else{
                [Byte[]]$BUFFER2 = New-Object Byte[] $PieceSize;
                $BUFFER.CopyTo($BUFFER2,0);
                while (@(Get-Job -State 'Running').Count  -ge $Threads){
                    Start-Sleep -m 50;
                }
                Start-Job -ScriptBlock $ScriptBlock -ArgumentList $BUFFER2,$NEWNAME,$Key,$BYTESREAD | Out-Null;
            }
	      ++$NUMFILE;
	    }
    }Finally{
        if($FileStreamReader){$FileStreamReader.Close();}
    }
}

Function Magic-Get([STRING] $File, [STRING] $Destination, [STRING] $Key){
    $ErrorActionPreference = "Stop"
	$Parts = @();
    $i = 01;;
    $PartPath = $File + $i.ToString("00") + ".AES";
    while(Test-Path $PartPath){
        $Parts+=$PartPath;
        $i++;
        $PartPath = $File + $i.ToString("00") + ".AES";
    }
    $Path = $Destination + "\" + [IO.Path]::GetFileName($File);
    if ((!$Path) -or ($Path -eq "")){
    	Write-Error "Target filename missing.";
		return;
	}
	if ($Parts.Count -eq 0){
	    Write-Error "No parts found.";
		return;
	}
    $Key2 = $Key | ConvertTo-SecureString -AsPlainText -Force;
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key2);
    $EncryptionKey = [System.Convert]::FromBase64String([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR));
    $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create("AES");
    $Crypto.KeySize = $EncryptionKey.Length*8;
    $Crypto.Key = $EncryptionKey;
    $FileStreamWriter = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Create);
    $isFirst=$true;
	if ($PSVersionTable.PSVersion.Major -ge 3){ # method CopyTo() is implemented in .Net 4.x first
		$Parts | foreach {
			"Appending $_ to $Path.";
            $FileStreamReader = New-Object System.IO.FileStream($_, [System.IO.FileMode]::Open);
            [Byte[]]$LenIV = New-Object Byte[] 4;
            $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null;
            $FileStreamReader.Read($LenIV,  0, 3) | Out-Null;
            [Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0);
            [Byte[]]$IV = New-Object Byte[] $LIV;
            $FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null;
            $FileStreamReader.Read($IV, 0, $LIV) | Out-Null;
            $Crypto.IV = $IV;
            $Transform = $Crypto.CreateDecryptor();
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write);
            $isFirst = $false;
			$FileStreamReader.CopyTo($CryptoStream);
			$FileStreamReader.Flush();
            $CryptoStream.FlushFinalBlock();
	  	    $FileStreamReader.Close();
		}
            $CryptoStream.Close();
	}
	else
	{ # .Net 3.5x
		[Byte[]]$BUFFER = New-Object Byte[] 100MB;
		$Parts | foreach {
		    "Appending $_ to $Path.";
		    $FileStreamReader = New-Object System.IO.FileStream($_, [System.IO.FileMode]::Open);
            [Byte[]]$LenIV = New-Object Byte[] 4;
            $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null;
            $FileStreamReader.Read($LenIV,  0, 3) | Out-Null;
            [Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0);
            [Byte[]]$IV = New-Object Byte[] $LIV;
            $FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null;
            $FileStreamReader.Read($IV, 0, $LIV) | Out-Null;
            $Crypto.IV = $IV;
            $Transform = $Crypto.CreateDecryptor();
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write);
	  	    while ($FileStreamReader.BaseStream.Position -lt $FileStreamReader.BaseStream.Length){
	    	    $BYTESREAD = $FileStreamReader.Read($BUFFER, 0, $BUFFER.Length);
	    	    $CryptoStream.Write($BUFFER, 0, $BYTESREAD);
	  	    }
            $CryptoStream.FlushFinalBlock();
            $CryptoStream.Close();
	  	    $FileStreamReader.Close();
		}
	}
    $FileStreamWriter.Close();
}
