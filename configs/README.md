# Configs

- **`inputs.conf`** — Universal Forwarder input configuration used on the
  victim endpoint (sanitized; no IPs or hostnames).
- **Sysmon config** — This lab used the community-maintained
  [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
  rather than a custom config, so it isn't duplicated here. Install with:

  ```powershell
  .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
  ```

## Notes on permissions

The Universal Forwarder runs under a Windows virtual service account
(`NT SERVICE\SplunkForwarder`) which does **not** have default read access to
the Sysmon Operational event log channel. If you see `errorCode=5` in
`splunkd.log` when trying to subscribe to
`Microsoft-Windows-Sysmon/Operational`, add the service account to the local
`Event Log Readers` group:

```powershell
Add-LocalGroupMember -Group "Event Log Readers" -Member "NT SERVICE\SplunkForwarder"
Restart-Service SplunkForwarder
```
