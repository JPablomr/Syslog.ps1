#
# Send data from your scripts to Syslog!
#
# Usage in a nutshell:
#   - . .\Syslog.ps1
#   - Edit the environment variables below.
#   - "Message" | Log-SyslogMessage | Relay-Syslog
#
# And that's it! 
# You can also tweak your message to have custom facility, severity, procid, and msgid, but this isn't needed.
#
#   - "Message" | Log-SyslogMessage -Facility 2 -Severity 7 -ProcId $PID -MsgId 'SampleMSG' | Relay-Syslog


# The program name reported to your syslog server.
$env:SyslogAppName = '-'

# Your syslog relay.
#   Syslog log messages are better when you send them to a server.
#   This environment variable controls the default relay for the Relay-Syslog function.
#
#   These are the URIs this script can handle:
#        - 'udp://server:port'
#        - 'tcp://server:port'
#        - 'tls://server:port'
#
$env:SyslogRelayUri = 'udp://127.0.0.1:514'


# Syslog formatted Timestamp
function Get-Timestamp {
    Get-Date -Format "yyyy-MM-ddTHH:mm:ss.ffzzz"
}

# This'll get your FQDN.
# On non domain joined computers, it'll add the workgroup name as your domain portion.
function Get-Hostname {
    (Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
}



function Log-SyslogMessage {
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string]$Message,
        [ValidateLength(1,48)]
        [string]$Appname = $env:SyslogAppName,
        [ValidateRange(0,23)]
        [int]$Facility = 1,
        [ValidateRange(0,7)]
        [int]$Severity = 5,
        [ValidateLength(1,128)]
        [string]$ProcId = '-',
        [ValidateLength(1,32)]
        [string]$MsgId = '-'
    )


    $Hostname = Get-Hostname

    $Timestamp = Get-Timestamp

    $Priority = "<$($Facility*20 + $Severity)>"
    $Version = 1
    # Maybe I'll implement this
    $Structured_Data = '-'

    "$($Priority)$($Version) $($Timestamp) $($Hostname) $($Appname) $($ProcId) $($MsgId) $($Structured_Data) $($Message)"
}


# Send Syslog Message Somewhere Else

function Relay-Syslog {
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $Message,
        $RelayUri = $env:SyslogRelayUri
    )

    $SyslogRelay = [URI]::new($RelayUri.tolower())
    
    switch ($SyslogRelay.Scheme){
         'udp' { Relay-SyslogUDP $Message $SyslogRelay.Host $SyslogRelay.Port }
         'tcp' { Relay-SyslogTCP $Message $SyslogRelay.Host $SyslogRelay.Port }
         'tls' { Relay-SyslogTCP $Message $SyslogRelay.Host $SyslogRelay.Port -tls }
         default {throw "OMG I don't know where to relay. Sorry!" }
    }
}

function Relay-SyslogUDP {
    param(
        [Parameter(Mandatory=$true)]
        $Message,
        $SyslogServer,
        $Port
    )
    $socket = New-Object Net.Sockets.UdpClient($SyslogServer, $Port)
    $bytes = [Text.Encoding]::ASCII.GetBytes($Message)
    $socket.Send($bytes,$bytes.length) | Out-Null
    $socket.Close()
}

function Relay-SyslogTCP {
    param(
        [Parameter(Mandatory=$true)]
        $Message,
        $SyslogServer,
        $Port,
        [switch]$tls
    )
    $socket = New-Object Net.Sockets.TcpClient($SyslogServer, $Port)
    $stream = $socket.GetStream()

    if($tls) {
        $stream = New-Object System.Net.Security.SslStream $socket.GetStream(),$false
        $stream.AuthenticateAsClient($SyslogServer)
    }
    else {
        $stream = $socket.GetStream()
    }
      
    $streamWriter = [IO.StreamWriter]::new($stream)
    $streamWriter.WriteLine($Message)
    $streamWriter.Close()

    $stream.Close()
    $socket.Close()
}