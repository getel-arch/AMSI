# AMSI

## Installing the AMSI Provider

1. Download the latest release

2. **Important**: Generate a unique GUID and update `AMSI_PROVIDER_GUID` in the provider code

3. Run the following command as admin

```
regsvr32.exe <amsi_provider_dll_path>
```

## Uninstalling the Provider

Run the following command as admin:

```
regsvr32.exe /u <amsi_provider_dll_path>
```

## Testing the Provider

1. Download the latest release

2. Run the following command

```
<amsi_consumer_exe_path> "<text_to_scan>"
```
