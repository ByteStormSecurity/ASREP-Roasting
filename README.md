# ASREP-Roasting
Deep Dive on ASREP-Roasting in C#
![Good Boi](goodboi.jpg)

## Static Compiling
The binary requires a BouncyCastle DLL. To statically compile it, use msbuild
```cmd
msbuild /t:Restore
msbuild /t:ILMerge
```

## Credits
- The ASN.1 Building Part from [HarmJ0y](https://twitter.com/harmj0y)'s [ASREPRoast.ps1](https://github.com/HarmJ0y/ASREPRoast/blob/master/ASREPRoast.ps1)
- Snippets of interacting with LDAP in C# from [SharpRoast](https://github.com/GhostPack/SharpRoast) 
