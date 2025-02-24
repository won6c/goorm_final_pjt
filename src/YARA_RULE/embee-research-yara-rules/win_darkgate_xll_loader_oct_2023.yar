
rule win_darkgate_xllloader_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/03"
		description = "Detects XLL Files Related to DarkGate"
		sha_256 = "091b7c16791cf976e684fe22ee18a4099a4e26ec75fa145b85dd14603b466b00"
		sha_256 = "305de78353b0d599cd40a73c7e639df7f5946d1fc36691c8f7798a99ee6835e7"
		sha_256 = "98c59262ad396b4da5b0a3e82f819923f860e974f687c4fff9b852f25a56c50f"
		sha_256 = "27ec297e1fc34e29963303782ff881e74f8bd4126f4c5be0c4754f745d85f79a"
		sha_256 = "392fd4d218a8e333bc422635e48fdfae59054413c7a6be764c0275752d45ab23"
		sha_256 = "9a34b32d0a66dd4f59aeea82ef48f335913c47c6ca901ab109df702cd166892f"

	strings:
		$s1 = "xlAutoOpen" wide ascii
		$s2 = { 49 ?? ?? 4c ?? ?? 48 ?? ?? 48 ?? ?? 02 e8 ?? ?? ?? ?? 48 ?? ?? 31 ?? 48 ?? ?? 01 48 ?? ?? 41 ?? ?? ?? ?? 30 ?? 48 ?? ?? 01 49 ?? ?? 75 ?? }
		
	condition:
			(all of ($s*))
		

}

/*

091b7c16791cf976e684fe22ee18a4099a4e26ec75fa145b85dd14603b466b00
305de78353b0d599cd40a73c7e639df7f5946d1fc36691c8f7798a99ee6835e7
98c59262ad396b4da5b0a3e82f819923f860e974f687c4fff9b852f25a56c50f
27ec297e1fc34e29963303782ff881e74f8bd4126f4c5be0c4754f745d85f79a
392fd4d218a8e333bc422635e48fdfae59054413c7a6be764c0275752d45ab23
9a34b32d0a66dd4f59aeea82ef48f335913c47c6ca901ab109df702cd166892f
e75db79573112919d4f22da890963a642424b7790e76cae59a0093aeaf56b000
84ce0d9800fbe7f3a058a6d912148087cbc2d0283fc58658d80d5a8c476a8cfd
f290ef5102313207aabb4e6987c155e86a38043fb4a762a9162e45c0892265ef
da8b00be0a7a8231c1203540e9673f33c1e382dacfff87f3cd18646e67e39d32
f00320f53433e878195a1ccf2461ec58de993cebc94d2c3d324f6df260e2a070
29286622f1895b43ebfc8988a86f405e1551d7c1a6d2d3436ce2a674de27290c
91518569d70bea3d89422f703c01b441428fb0de3aa5a46cd3dc7bc462119fd5
c60eff3d32eabace9781bc6afb6605f628ead25914c679989d4f9ca76d7f683b
2677822baff59b35030c649316f838766848b9be1676e01dd4121b264ae6a3ba
6c5afecac15525d8e8b3a96d045839975e7cd461ba759a925858c91bab5bc006
edaee17fdd77e36335e06991132c51d0a960003e141a02af509a6d951a268494
4a86d08ae737b790f253552c63607cc252732e23d674f171b9451ce7a0dade2f
7e13de7599045020d8cdbf4b3f8a3cda1d9bcddedb973ad63d024d84781b0f80
a0b77ac2a92756f1d286b260109ea775d8c07aacaf6f813a447cff50a4abbd2b
79e13fb9f2d9b5baddba2989890e1a4371a9f0ddb93cf4f6f0da55501f0b5287
df9ec17b67faa06933e3e982d8f6c5dbedab139beac899a69f1dfd54933c2be5
8f9a701dfd058342ee509e092da0bdbea7bd8756c105a3d2702d80e3d5037369
15efaafae570e4e5e3b2414a7996c97bd6039e82738c396e4a495d448b148df4

*/