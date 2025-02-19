import "dotnet"

rule win_solarmarker_bytecodes
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/09/10"
		description = "Detects bytecodes present in solarmarker Packer"
		sha_256 = "a433dad1e31f2e19ab5d22b6348c73fa4c874502acc20d5517d785b554754279"
		
	strings:
		$s1 = {8C ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 20 ?? ?? ?? ?? 13 ?? 06 11 ?? 20 ?? ?? ?? ?? 58 D1 8C ?? ?? ?? ?? 28 ?? ?? ?? ?? 0A 20 ?? ?? ?? ?? 13 ?? 06 11 ?? 20 ?? ?? ?? ?? 58 D1 8C ?? ?? ?? ?? 28 ?? ?? ?? ??}
		
		
	condition:
			dotnet.is_dotnet 
		and
			filesize < 7000KB 
		and 
			$s1
}     


