# OpcUa_any BrowsePath notes

The generated configuration uses **StartingNode empty** and a complete **RelativePath from Root**, for example:

```text
StartingNode: (empty)
RelativePath: /0:Root/0:Objects/2:DeviceSet/2:X20BC008U/2:X2X/2:SubDevices/2:ST2/2:ProcessData/2:DigitalInput01
```

This is illustrative: relative index `2` is valid only if the corresponding namespace URI is configured as index `2` in Automation Studio. The GUI currently builds a relative index table from the namespaces used by matched nodes.

If several nodes share the same BrowseName, select the correct result by its displayed parent path.

Review path syntax and namespace URIs in a real AS configuration before using in production.
