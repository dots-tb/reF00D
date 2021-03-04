/*
 * reF00D
 * Copyright (C) 2021, FAPS TEAM
 */

#include <psp2kern/types.h>
#include "self.h"
#include "ref00d_types.h"
#include "ref00d_kprx_auth.h"

const SceKprxAuthKey kprx_auth_key_list[REF00D_KPRX_AUTH_KEY_NUMBER] __attribute__((aligned(0x20))) = {
	{
		.key = {
			0xEF, 0x03, 0xF8, 0xB0, 0x57, 0x2B, 0x60, 0x5E, 0x94, 0x42, 0x48, 0x5D, 0x85, 0x53, 0x71, 0x99,
			0x8F, 0xA9, 0x3D, 0xDE, 0x0B, 0x38, 0x63, 0x05, 0x66, 0x1B, 0x84, 0x61, 0x9F, 0xB4, 0x66, 0xED
		},
		.iv = {
			0x23, 0x2C, 0xCB, 0x1A, 0x70, 0xF5, 0x13, 0x07, 0x63, 0xD6, 0xEC, 0x90, 0xBC, 0x6C, 0x08, 0x00
		},
		.minver    = 0x6E450441EAA30E2B,
		.maxver    = 0xD5F9E4439A1B42B2,
		.rsa_n = {
			0x2E1478CD, 0xCB4E3A67, 0x8C37B2D2, 0xF0C5FE68,
			0x67C998AC, 0x69C38187, 0x88A366A3, 0xE17BCF1A,
			0x7AC9EDCC, 0x9CA453BF, 0x2B1EA734, 0x83CBDD94,
			0x02D09D07, 0x0AEE0C72, 0x58CCA624, 0x90CDD028,
			0x8895B6B8, 0x6AE757A0, 0x17494D7C, 0xB025DB2A,
			0xF28DBC3C, 0xF0345FD2, 0xA65FC394, 0xA8C023CB,
			0x3F544A99, 0x1FB815FB, 0x8E96AAE5, 0x57D9FD6A,
			0x5E7C0493, 0x3DAD264D, 0x03B6AA81, 0x2CFD2D4B,
			0xB0CE66D0, 0x4D3F1469, 0xD48E45DD, 0x27DCFAE7,
			0x9E57B84F, 0x72F9EFC8, 0xB7199BCA, 0xEE5FA2D7,
			0x42157521, 0x5DC45F3C, 0x765DBE42, 0xEAA6886B,
			0xDDAA8FDE, 0x2CD04D9C, 0xBE3B588D, 0xE6696CF7,
			0x2FD9EEC9, 0xBAAD9C5E, 0x38A8B766, 0x96FFBD3C,
			0x3C7D3B7D, 0xD9213E94, 0x4AB04384, 0xA00ACA11,
			0x311BF5B6, 0x67912DEE, 0x7C86376B, 0x65C335C5,
			0xE1B96E02, 0x013114A0, 0x1763AD94, 0x629C1EEA
		},
		.sce_type  = 0x3C52B915,
		.key_type  = 0xD8636CFE,
		.self_type = 0x41E7CC41,
		.key_rev   = 0x54FA42AE,
		.flags     = 0xD707925D,
		.dbg_key_name = {
			0x30, 0x0A, 0x39, 0xCA, 0x5C, 0x06, 0x9C, 0xFD, 0xA1, 0xB0, 0xFD, 0xD1, 0x14, 0xF7, 0x93, 0x3D,
			0xCC, 0x15, 0xAD, 0x87, 0x72, 0x6A, 0xEC, 0xD4, 0xC2, 0xE9, 0x2E, 0x7A, 0x94, 0xB8, 0x6B, 0x9C,
			0xC0, 0x90, 0x89, 0x9A
		},
		.magic     = 0x3CA747E6,
		.hash      = 0xE94E4BA6
	},
	{
		.key = {
			0x6F, 0x2A, 0xB8, 0x66, 0x09, 0x23, 0x83, 0xF5, 0x87, 0xE0, 0x39, 0x2F, 0xE3, 0x1E, 0x0B, 0xD1,
			0xBF, 0x8F, 0xA6, 0x43, 0xA3, 0xE0, 0x85, 0x66, 0xA7, 0x8D, 0xED, 0xA7, 0x57, 0x70, 0x89, 0x5E
		},
		.iv = {
			0x5E, 0x17, 0xBE, 0x29, 0x13, 0x05, 0x44, 0x79, 0x81, 0x58, 0xC5, 0x5C, 0xD4, 0xD6, 0x07, 0xF3
		},
		.minver    = 0x3F624746C0B80EF0,
		.maxver    = 0xC0408DDB55F73D6A,
		.rsa_n = {
			0x3B89BB9A, 0xA526EAE3, 0xA5C86EE2, 0xD9C4726C,
			0x6A1135DA, 0xBF397742, 0x91EC7AA8, 0x0771B18B,
			0xAC6ADC26, 0xED6C774E, 0xEC6886CE, 0xBEE2C53B,
			0xB37A70DC, 0x65575105, 0xB081F64C, 0x719B77A0,
			0x633DB284, 0xFD1D5D99, 0xDB4BEAAC, 0x1B09737C,
			0xE30557FB, 0x7B1519FF, 0x816C25DD, 0x0A8ED420,
			0x265DDC1B, 0x34777540, 0xB0354135, 0xFD02F503,
			0xC27C8EB3, 0x48961E12, 0x1A7BA8A6, 0xB2D1434D,
			0x29E1B95C, 0xDCE8C3B8, 0x1C94D141, 0xEEC4E2E8,
			0x2D57FEE8, 0x5C6DFD11, 0xF3182298, 0xB996F143,
			0x7726DE3C, 0x1C41CAD0, 0x5149178A, 0x02318992,
			0x8C36F24D, 0xD928AAFE, 0x6EE52560, 0x667D74BC,
			0x3FFBD1DA, 0x56B21874, 0x8D73DE57, 0x6D07E76A,
			0xEC01999E, 0x0CEDC1C2, 0x9D69E9A0, 0xDAD7D1C9,
			0x4AE78C1A, 0x6AD86D46, 0x2EE6ADF1, 0x2DAF067B,
			0xE0088068, 0xDE2FD97E, 0xABA6A3E8, 0x4BC3DD8D
		},
		.sce_type  = 0xD8FF7ACD,
		.key_type  = 0x38C6DCAA,
		.self_type = 0x6F249229,
		.key_rev   = 0xCADDCAE4,
		.flags     = 0x095D0306,
		.dbg_key_name = {
			0xC9, 0xCD, 0xBD, 0xFB, 0xE6, 0x90, 0x3E, 0x54, 0x4C, 0xDB, 0x9B, 0x30, 0xB0, 0x30, 0x8A, 0xF0,
			0xF6, 0x4A, 0xF3, 0x0A, 0x82, 0x5C, 0xA8, 0xD1, 0x84, 0xBF, 0xCA, 0xD8, 0x0E, 0x38, 0x08, 0xD4,
			0x1C, 0x3B, 0x15, 0xAD
		},
		.magic     = 0x6E805F73,
		.hash      = 0x27CA354A
	},
	{
		.key = {
			0x15, 0x3E, 0xE4, 0x0C, 0x86, 0x32, 0x64, 0x03, 0xAF, 0x34, 0x26, 0x42, 0xAA, 0x6D, 0x0D, 0x19,
			0x23, 0xC1, 0x86, 0x2A, 0xCB, 0xB7, 0xC5, 0x43, 0x79, 0x3E, 0xFB, 0xCC, 0x49, 0x0C, 0xE0, 0x86
		},
		.iv = {
			0x97, 0x52, 0x64, 0xD4, 0x47, 0xA0, 0x15, 0x99, 0x05, 0x0A, 0xCA, 0x7B, 0xD3, 0x0E, 0x56, 0x45
		},
		.minver    = 0x8474FE7BABDD160E,
		.maxver    = 0x5F892F0993FAD265,
		.rsa_n = {
			0x96E0C72C, 0xB98A58E4, 0x7BAB65EE, 0xF1852158,
			0xEEE38147, 0xC75D8368, 0xD42B9EEF, 0x1C49FE1B,
			0xCCBF0D28, 0xDE2E5E17, 0x40BAE499, 0xF5A4285D,
			0x09F501C1, 0x5DD87DFB, 0x90012056, 0x7F4D0AAD,
			0x363F8CB9, 0x9C67689A, 0x6837C653, 0x7D7E317B,
			0x66B2B517, 0x02500761, 0x8F9CF792, 0x4D89B4C8,
			0xE943FD16, 0x48334681, 0xBA2A68BE, 0xC9AD474D,
			0xA9AA509D, 0x976764D5, 0xC633FC3B, 0x7108C516,
			0x4A603CDE, 0xD8707F1B, 0xCDD44A67, 0xF610F8F0,
			0x01C28BCD, 0xFBD4B770, 0x7CE0A2C1, 0xB370DFC6,
			0x05412CBA, 0x5C685DFE, 0x1283D683, 0xFAE4A0FA,
			0xE0B74BAD, 0xEDA9DB5E, 0x0A494C7A, 0x30CAFB67,
			0x75D767AD, 0xBB5576A9, 0x17905567, 0x672A3CCB,
			0xE5E01647, 0x4EAC970D, 0xFC4C2712, 0xE8062728,
			0xE1274245, 0x7FA12350, 0x470A2827, 0x9D715881,
			0xE25DB37C, 0x4FA48593, 0xEA3CED6B, 0x140A17CE
		},
		.sce_type  = 0x39896E55,
		.key_type  = 0xFD9B9BD6,
		.self_type = 0xE14E525C,
		.key_rev   = 0xDCDEA93B,
		.flags     = 0xD8F6AE08,
		.dbg_key_name = {
			0x5E, 0x6F, 0xB4, 0xA9, 0x2C, 0xB8, 0xDB, 0xEF, 0xEA, 0xCB, 0x33, 0x31, 0xE1, 0xEE, 0x9A, 0x34,
			0x7A, 0xB0, 0x3C, 0xBF, 0x7D, 0x74, 0x7A, 0x8B, 0x44, 0xD8, 0xEB, 0x8B, 0x32, 0xCC, 0x77, 0x40,
			0x3D, 0xA7, 0x41, 0x11
		},
		.magic     = 0xF2F9AC21,
		.hash      = 0xF25CCD92
	},
	{
		.key = {
			0x28, 0x73, 0xA8, 0xAD, 0xE8, 0x72, 0x00, 0x7B, 0x6E, 0xF8, 0xE3, 0x01, 0xC4, 0x9D, 0xE3, 0x6D,
			0x4C, 0x6E, 0xBB, 0xA2, 0xDC, 0xA1, 0x9B, 0xCD, 0x06, 0x7B, 0xE4, 0xC4, 0x32, 0x80, 0xF9, 0x17
		},
		.iv = {
			0xDB, 0x9D, 0x38, 0xB4, 0xE2, 0xE9, 0x7D, 0xAF, 0xC7, 0xAF, 0x2D, 0xFE, 0xF7, 0xA5, 0x5A, 0x2D
		},
		.minver    = 0xBE8A71FBF0AFE44B,
		.maxver    = 0xDCF7160A297ED,
		.rsa_n = {
			0xDE225CAA, 0x6165F8BE, 0x680E2644, 0xAB86E9B9,
			0x061E0C43, 0x745E5634, 0x438E27A9, 0x528CD574,
			0x25D48503, 0xB0E180A6, 0x653799C7, 0x3C4C9D58,
			0xDF84F00B, 0xB658906C, 0x2502596C, 0xD2F47270,
			0x8CDAC3D5, 0x92C9B969, 0x6BB6E49F, 0xD3B06105,
			0xF52F9C8C, 0x5CF2B12A, 0xB014BD92, 0x0A91BAD1,
			0x1F265495, 0xD9906D30, 0xA190D36B, 0x61CA8B95,
			0x86936BA6, 0xB4C291CE, 0xA7636390, 0x43D24528,
			0xB1AF26E5, 0x3D161720, 0x1C25AA84, 0x0DEFA0E0,
			0x4AB37EEA, 0xC94A03AE, 0xAE376FED, 0xB999EEA8,
			0x90AD9925, 0x42B275F6, 0xF87B0B3E, 0x30CCC5D8,
			0x01DD8C7A, 0x6994AA75, 0x1BBBE82B, 0xC4FFFD26,
			0x7DACD83C, 0xF7068526, 0xF8F22C95, 0x1B927576,
			0x2182C02E, 0x4E632785, 0x771627CE, 0x98D3806F,
			0x745ECEAD, 0x790A54E1, 0x7D272C82, 0xC093E67E,
			0xC54744FA, 0x15CB516B, 0xE1B8E4A0, 0xB2C45D6C
		},
		.sce_type  = 0x8A760E85,
		.key_type  = 0x8DE9E213,
		.self_type = 0x6FC9A869,
		.key_rev   = 0x75992289,
		.flags     = 0xDBC8CB60,
		.dbg_key_name = {
			0x02, 0x97, 0x68, 0x0B, 0x1C, 0xE1, 0x28, 0x1B, 0x71, 0x27, 0xC5, 0x4B, 0x33, 0x4F, 0x19, 0x47,
			0x13, 0xA9, 0xA3, 0x57, 0x5F, 0x8C, 0x60, 0xFE, 0xBD, 0xB7, 0xF8, 0xB6, 0xAC, 0x91, 0x8A, 0x1F,
			0xFB, 0xE2, 0x4E, 0x71
		},
		.magic     = 0x3CBD44C0,
		.hash      = 0x90183FDC
	},
	{
		.key = {
			0xEF, 0x97, 0x64, 0x9B, 0xF5, 0x82, 0x95, 0xE4, 0xEF, 0x68, 0xC7, 0x7B, 0x58, 0x30, 0xC8, 0x90,
			0x1A, 0x34, 0x94, 0x61, 0xD1, 0x43, 0x74, 0xEE, 0xF2, 0xDA, 0x57, 0xD4, 0x62, 0x06, 0x6D, 0xC9
		},
		.iv = {
			0x4D, 0xBE, 0xBA, 0x6B, 0xCE, 0x84, 0xE5, 0x12, 0x94, 0x77, 0x93, 0xB2, 0x6D, 0x37, 0x70, 0x6E
		},
		.minver    = 0x9747970E0182564B,
		.maxver    = 0x5094B5EB8749D3BA,
		.rsa_n = {
			0x1EE6DB04, 0xD34077BF, 0x2AAAD18F, 0xB1A60FFE,
			0x56D695DA, 0x7D054680, 0xA77F9B5D, 0xA220F593,
			0x27027FC6, 0xB9DA20A2, 0x2DC4FA55, 0xD85B9803,
			0xED54EBE6, 0x56645628, 0xF498E69E, 0x0727F663,
			0x1201BD14, 0x267A684B, 0x6241EE7F, 0xF664FEE9,
			0xD9D1215B, 0xF6494E2C, 0xB3D5CD91, 0xED28C72E,
			0x7121ABBD, 0x53DADFD4, 0x06CF953C, 0xD7BF5499,
			0x3F2EF136, 0x862BBE70, 0xA4D83B43, 0x683EC45E,
			0x730490D5, 0x76BCD8B3, 0xC0937C33, 0x8C805696,
			0x637DA2D6, 0x1824027B, 0x63F748EC, 0x9AAA43A1,
			0x5CF81C80, 0x0ACFF8C6, 0x65B380FA, 0xBCE34AD5,
			0x9F7817DE, 0x041CF176, 0xBA29DF03, 0x5351780A,
			0x41873FB3, 0x4DF60852, 0xCC45F442, 0xECB38C9B,
			0x28B53670, 0x7A33586A, 0x023D4B6D, 0x3F7E6316,
			0xE271A669, 0xFCDAB883, 0xEC1C1810, 0xF44CDAF7,
			0x5BA566E0, 0x79F8F00A, 0x618EC739, 0x38447C38
		},
		.sce_type  = 0xC8AD3CBD,
		.key_type  = 0x4C108C94,
		.self_type = 0x62BA3589,
		.key_rev   = 0x6D1036CD,
		.flags     = 0x6CBF8CCB,
		.dbg_key_name = {
			0x8B, 0x2E, 0x3F, 0xBD, 0x41, 0x8F, 0xFA, 0xDF, 0xBE, 0xB9, 0x42, 0x15, 0x3E, 0xFF, 0x2D, 0x8E,
			0xE6, 0xB3, 0xFF, 0x3A, 0xB8, 0x0F, 0xAE, 0x31, 0xB5, 0x49, 0x9A, 0xDA, 0x77, 0x17, 0xF1, 0xDB,
			0x63, 0x42, 0x0C, 0x01
		},
		.magic     = 0x2AAD37BF,
		.hash      = 0xFADF6E10
	},
	{
		.key = {
			0xF2, 0x28, 0xC8, 0x9D, 0x61, 0xAC, 0xCD, 0xD5, 0x08, 0xF0, 0xA3, 0x34, 0xBA, 0x4D, 0x27, 0x53,
			0x6B, 0x2E, 0xCE, 0x34, 0x90, 0xD7, 0xFA, 0x61, 0x9C, 0xA6, 0x8F, 0x66, 0x0A, 0x27, 0x06, 0x2A
		},
		.iv = {
			0xFA, 0x36, 0x95, 0x11, 0x0D, 0x91, 0x86, 0xAB, 0x6D, 0xCD, 0x4B, 0xA7, 0x8F, 0xCB, 0xA3, 0x14
		},
		.minver    = 0xBBD743FDAE4304E,
		.maxver    = 0x61657EBAD36D5EE3,
		.rsa_n = {
			0xF60A14AE, 0xE3DC500A, 0xDE209D2B, 0x8D703C61,
			0x309F98DE, 0x4286A5B2, 0x8BE4AF41, 0xA3A8AC28,
			0x6031749B, 0x410FC02B, 0x1FFC2AC4, 0xBE9BB72E,
			0x3F17D9BE, 0x2BF58042, 0xB482DD68, 0xCBB88F4B,
			0x03047663, 0x2FDEFB08, 0x9C902BFC, 0x7B5CFF46,
			0x56AE30BD, 0xBC828B49, 0xE406B601, 0xEEF5EE00,
			0xEC30D4AD, 0x008A4F4F, 0xCAFE6939, 0x5DA90549,
			0xC5A0ECC1, 0x42B80486, 0xC801A04D, 0x486895DF,
			0x03F01995, 0x8DB1A915, 0x74D4C9C0, 0x614F593B,
			0xC38E6075, 0x69CBEFED, 0x83299AC6, 0x92233952,
			0xA8AA3A58, 0xE6D1D566, 0xCD15474B, 0x740BA357,
			0x065E16B5, 0x7B033F1A, 0x5BC86F60, 0x56801A55,
			0xABF0C7CC, 0x3E976200, 0xE4BA938E, 0x9D83F3FD,
			0x5D996C78, 0xA3045417, 0xAEBE37EE, 0x0585202B,
			0x95A653E8, 0x6167792A, 0x8D66A6FB, 0xFCF21125,
			0xAF2B56A9, 0x62EA6F98, 0x345526DA, 0xF83605EE
		},
		.sce_type  = 0xC10B8367,
		.key_type  = 0xB7CEAA44,
		.self_type = 0xA7B83812,
		.key_rev   = 0x7F1D03EA,
		.flags     = 0x0BA39849,
		.dbg_key_name = {
			0x02, 0x99, 0xCF, 0xAA, 0xB7, 0x52, 0x39, 0x2E, 0x84, 0x27, 0xB0, 0x1C, 0x5D, 0x4F, 0x19, 0xDE,
			0xAA, 0xB6, 0xDF, 0x3A, 0x9C, 0xB5, 0x12, 0x13, 0xBF, 0x9B, 0x76, 0x16, 0xC1, 0x0D, 0x02, 0xF1,
			0xB0, 0x79, 0x7A, 0x5E
		},
		.magic     = 0x515109DD,
		.hash      = 0x79F672CF
	},
	{
		.key = {
			0x49, 0x12, 0x76, 0x00, 0x74, 0x57, 0xFC, 0xC2, 0x94, 0x85, 0x23, 0xC1, 0x3B, 0x26, 0x81, 0xB5,
			0xF3, 0x4E, 0xD9, 0x52, 0x6C, 0x75, 0xC3, 0xA5, 0xF1, 0xED, 0x41, 0x84, 0xF8, 0x6A, 0x02, 0x04
		},
		.iv = {
			0xB3, 0xE4, 0xBB, 0xA7, 0x0C, 0x4B, 0x29, 0xA8, 0x46, 0x65, 0xED, 0x1E, 0xE1, 0x10, 0x29, 0x55
		},
		.minver    = 0x7B3DD93ED8AF44EE,
		.maxver    = 0xF9E86C31DC17407E,
		.rsa_n = {
			0xB3CD66C3, 0xD744601D, 0x16C45048, 0x490B8D2F,
			0x77CE4813, 0x276C2B4D, 0xF28AB68B, 0x82A5DAEB,
			0x85E2A8DD, 0xD65B28E3, 0x3D4EEE7D, 0x971A85E4,
			0xCB5BAE81, 0xE5AC62CA, 0xEC9944C6, 0x133340A3,
			0xACBC0673, 0xA1556D16, 0xCD5FFB60, 0x4192640D,
			0x02DBA9ED, 0xEF6B2B0A, 0xB60AABDD, 0x2040D32B,
			0x384E1EAF, 0x883F0FBF, 0xAC4269AE, 0x5FCBFA9E,
			0x112F984C, 0x169A4397, 0xF65FCC60, 0x14272B3C,
			0x64AA2C8D, 0x53276166, 0x6CC6B283, 0xFAE36AAC,
			0x5D73B6B3, 0x85517599, 0xDCA958EB, 0xA69EE4B5,
			0xC6203ABF, 0x8DE91AE2, 0x0FBAABBD, 0x85035DEB,
			0x318D564B, 0x9A2D3299, 0x087AB0F4, 0x2E3035CF,
			0xE8AAB453, 0x3E8D3C66, 0x1AC3DD9D, 0xD9C65E6E,
			0x418A8E9B, 0x4E5FC6AF, 0x05080C68, 0x7EC350DB,
			0x731230C0, 0xC5A99C89, 0x10C05484, 0x04428E96,
			0x893AE7BF, 0xDC261DEA, 0xDB10DB42, 0x4418E68D
		},
		.sce_type  = 0x9105A442,
		.key_type  = 0x342F16A1,
		.self_type = 0xC1C2B84A,
		.key_rev   = 0xF70BD569,
		.flags     = 0x61792A18,
		.dbg_key_name = {
			0xC5, 0x47, 0x55, 0xF8, 0x1D, 0x6E, 0xF3, 0x6C, 0x0B, 0xA8, 0xAC, 0x47, 0x14, 0x89, 0xD1, 0xCD,
			0x7F, 0x27, 0x94, 0xE8, 0x81, 0x0B, 0x47, 0xCB, 0xE1, 0x2C, 0xA2, 0x89, 0x78, 0xCF, 0x1A, 0x49,
			0xFF, 0x98, 0x4E, 0x47
		},
		.magic     = 0xD188F554,
		.hash      = 0xD0E67B4F
	},
	{
		.key = {
			0x08, 0x5B, 0x52, 0x49, 0x4A, 0x2D, 0x7E, 0x89, 0x2F, 0x29, 0x2F, 0x10, 0xED, 0x70, 0xB4, 0x24,
			0xDD, 0x65, 0x1F, 0xED, 0xC9, 0x73, 0xC9, 0x3C, 0x5A, 0x7A, 0x5F, 0xF3, 0x5B, 0x90, 0xD9, 0x16
		},
		.iv = {
			0x3F, 0x66, 0x9E, 0x44, 0x13, 0x97, 0x07, 0xB6, 0x95, 0x21, 0x65, 0x5A, 0x63, 0x62, 0xEF, 0x23
		},
		.minver    = 0x759621332CE25E05,
		.maxver    = 0x6195F7337D45269B,
		.rsa_n = {
			0xF7C7A98D, 0x4D4B179F, 0x79BB6373, 0x6B21F9F2,
			0x538F3725, 0x0A25CC36, 0x2788A90E, 0x559FE21B,
			0x1291D4BF, 0x57DC22A6, 0xF49C96EC, 0x96ABF4DA,
			0x7575F4EB, 0x03E62FCC, 0x127DD7C2, 0x226D6DC5,
			0x3D4F5BE3, 0x28F500B8, 0x8D3442C0, 0x834ACF22,
			0x0011DFD2, 0xDDB45BB9, 0xEE02545F, 0x3E42B47C,
			0xC2E8854A, 0x59806310, 0x8BE71C8E, 0x0BF9EA3D,
			0xB7C10671, 0xB1696EC9, 0x140115AB, 0xE6BF8A8E,
			0x3A6C3BDE, 0x6401D3A6, 0x02A4CC3C, 0x3369F343,
			0x3067FD8A, 0x3E85FD16, 0xED832570, 0xDA088ED7,
			0x112232E7, 0xE9D846A4, 0x7F588FAC, 0x8388A29D,
			0xE8033A0F, 0x3C60C87B, 0xA50B8BB5, 0x04084757,
			0xADF92423, 0x89FAA239, 0x1CE6010B, 0xE1A3801E,
			0xDAA0A37E, 0x53F22CE1, 0xC626AB3B, 0x10FC4080,
			0x29094097, 0xCCA22070, 0xEF59157B, 0x2BE44AD5,
			0x5DD60A38, 0x5348FB69, 0xA6015E13, 0x65B58D3E
		},
		.sce_type  = 0x103F98F7,
		.key_type  = 0xD633D23D,
		.self_type = 0xD46AD98C,
		.key_rev   = 0x1377A00C,
		.flags     = 0x7CBFAA17,
		.dbg_key_name = {
			0x68, 0x79, 0xE5, 0x5E, 0x37, 0x2D, 0x2B, 0x5B, 0x4F, 0xE8, 0x23, 0x21, 0xA7, 0x10, 0x2C, 0x7D,
			0xE7, 0x6E, 0x8C, 0x94, 0x9E, 0x54, 0x5C, 0x65, 0xB2, 0x8E, 0xF5, 0x89, 0xAE, 0xEB, 0xE4, 0x18,
			0x20, 0x82, 0x43, 0xA8
		},
		.magic     = 0x326B4367,
		.hash      = 0x395DDB4C
	},
	{
		.key = {
			0x76, 0xB8, 0xC5, 0x2D, 0x8A, 0x6A, 0x1C, 0x81, 0x31, 0xED, 0xFB, 0x8E, 0x53, 0x90, 0x1B, 0x8A,
			0x65, 0x66, 0x8E, 0xB4, 0xC1, 0xAE, 0xEE, 0x7F, 0x1D, 0x18, 0xD3, 0x4E, 0xB4, 0x6D, 0x3F, 0x1B
		},
		.iv = {
			0x32, 0xF4, 0xDC, 0xE7, 0x48, 0x19, 0x0C, 0xDC, 0x3E, 0xD4, 0xDD, 0xE5, 0x2E, 0xEF, 0x31, 0x56
		},
		.minver    = 0xF56391AD879B6274,
		.maxver    = 0x3D6E679CE7D5058F,
		.rsa_n = {
			0x2C4E3F60, 0xD6869F6C, 0xAAC7A963, 0x16D8290F,
			0x87FD257A, 0x1A9CF458, 0x1059916F, 0x3C3E4424,
			0x95EA5345, 0xD220EF3B, 0x03CE506F, 0xE347F93C,
			0xF28BD897, 0xDA037E0C, 0x0E854C30, 0x2D28A410,
			0x44A8AF76, 0x6EA57D65, 0xA60392EC, 0x8897F7E7,
			0x84755149, 0x42F08087, 0x31C14C7C, 0x40B15F20,
			0xF3D7B8C2, 0x4D897D30, 0xEAA17BF9, 0x2841ED6C,
			0xD5609846, 0xB05BD7C1, 0xFF756B83, 0x65DDFD5F,
			0x11FCD5EA, 0x9AADADF2, 0x4EEFB7C3, 0x95560374,
			0x362C72D2, 0xE856654B, 0x390281DE, 0x4F9CB6DF,
			0x6BD7E889, 0xF61E6FA3, 0xCC2E45DF, 0x0C8E3448,
			0xB8D36CAF, 0x2839736B, 0x0AEDEDFC, 0x250EF8B8,
			0x2E70118F, 0x4F88E5DF, 0xB983C464, 0xE09169DB,
			0x4936F4ED, 0x5D0AF257, 0xC86F4C2D, 0x0EBBD026,
			0xC95D2844, 0x310B5E41, 0x8A722E78, 0x605D28BF,
			0x41E594D3, 0x34703063, 0xA93848C2, 0xB753A760
		},
		.sce_type  = 0xDCC2BC7D,
		.key_type  = 0xE28F33AD,
		.self_type = 0x6A68C515,
		.key_rev   = 0x5EB9EB72,
		.flags     = 0x0EEB4098,
		.dbg_key_name = {
			0x3C, 0xC2, 0x39, 0xFB, 0xDD, 0x40, 0x6C, 0xB0, 0x8F, 0x0D, 0xF9, 0xFB, 0xBA, 0xDF, 0x66, 0xAF,
			0x7F, 0xFC, 0x68, 0xD8, 0x3B, 0x33, 0xF0, 0xD4, 0xF4, 0xF8, 0xF1, 0xC9, 0x3F, 0x29, 0xCE, 0x48,
			0x00, 0x3B, 0xC0, 0xBA
		},
		.magic     = 0x6371CC94,
		.hash      = 0x79C92EA3
	},
	{
		.key = {
			0x59, 0x1C, 0xC1, 0xCB, 0x8A, 0x0E, 0xFA, 0x11, 0x27, 0x58, 0x76, 0x0F, 0xAE, 0xC5, 0x25, 0x31,
			0xEC, 0x57, 0xF4, 0x51, 0x5E, 0x12, 0xFD, 0x0F, 0xC2, 0x32, 0x91, 0x32, 0x86, 0x80, 0x17, 0xCB
		},
		.iv = {
			0xEC, 0xB0, 0xF7, 0xF7, 0x81, 0xC8, 0xFB, 0x2C, 0x77, 0x42, 0xFE, 0x02, 0xC5, 0x6B, 0xBA, 0x75
		},
		.minver    = 0x1EF32B931696C095,
		.maxver    = 0xA5A2381931A7044A,
		.rsa_n = {
			0x82D2C0B9, 0x5BC6FB8F, 0x294B553E, 0xACE46A1B,
			0x9D1E9DBF, 0x3A095DE3, 0x9CC26425, 0x9FEE0232,
			0x77515C48, 0xF0F0B777, 0x733AEF3C, 0x6FE6CA3C,
			0x24DF52F3, 0xB08E0137, 0xD290A9B3, 0x29DBC863,
			0xB0A74052, 0x3A38E420, 0x99B6450A, 0x879FDC31,
			0xFA01958A, 0xE9CF36E8, 0x49C8D836, 0xAEDB459E,
			0xB641B654, 0x1313A8A0, 0xF60CCE7C, 0xB2859EF8,
			0x4A24D973, 0x28380FDF, 0x506029BC, 0xF26CCEEC,
			0xE418F75C, 0x182523FE, 0x8C52C9CA, 0x92268789,
			0x96927FC3, 0xFB724A79, 0x91B6FF6B, 0xE9C9C6A3,
			0xDABF0EFD, 0x5279037E, 0xADE413B7, 0x65FF0279,
			0x8688E445, 0x9684C390, 0xD0DC2FFD, 0x008FDB29,
			0x3A5D27AA, 0x958616D2, 0x1AFAE9EA, 0xCB5B84ED,
			0x8833B251, 0x11E40D3B, 0xC63BEA1F, 0x57080B46,
			0x1F3947AC, 0xF3B7042B, 0x98BA5650, 0x2DCD1075,
			0x14522B6E, 0x193EA9BC, 0x5799F624, 0xCC55F9EF
		},
		.sce_type  = 0x9FA375B1,
		.key_type  = 0xB7CB6ECB,
		.self_type = 0xF1B69091,
		.key_rev   = 0x86FD8216,
		.flags     = 0x427C78AA,
		.dbg_key_name = {
			0x2F, 0x20, 0xC9, 0xC5, 0xE9, 0xF0, 0x6A, 0x98, 0xEC, 0x1D, 0x4F, 0x97, 0x48, 0xC4, 0x32, 0xB7,
			0x54, 0x49, 0x87, 0x7B, 0x7C, 0xAF, 0xC8, 0x23, 0x8B, 0x08, 0xC9, 0x2F, 0x94, 0xA1, 0x3C, 0xE3,
			0xF1, 0xF7, 0x3B, 0xD1
		},
		.magic     = 0x348C49D1,
		.hash      = 0xBDAE326E
	},
	{
		.key = {
			0xEB, 0x26, 0xF3, 0x2B, 0x46, 0x6F, 0x3D, 0x30, 0xEB, 0x74, 0xD5, 0x11, 0x49, 0x25, 0x9C, 0xA4,
			0x38, 0x69, 0x2D, 0x19, 0x02, 0xE8, 0x67, 0xE4, 0x78, 0x84, 0xD9, 0xBA, 0x17, 0x2C, 0x34, 0xC9
		},
		.iv = {
			0xED, 0xC4, 0x51, 0xEC, 0xA3, 0x69, 0x4B, 0x34, 0xF5, 0x88, 0x78, 0x04, 0x32, 0xC3, 0x26, 0xF5
		},
		.minver    = 0x9ACB346D1C790E5F,
		.maxver    = 0x5304679B7B34FCA8,
		.rsa_n = {
			0xA943E142, 0xE00C4E2E, 0x9A1391A5, 0x50CACA3C,
			0x81FCC856, 0x7FC562B0, 0x40A0FD5A, 0x114A1231,
			0xAB87207A, 0x7FF62E19, 0xE1C0BACF, 0xC6F19AAF,
			0xA8824D05, 0xD1ADCF18, 0xE3909CF5, 0x1343815C,
			0xB8772E82, 0x4F124DCE, 0x39E8CC2B, 0x38BC77A6,
			0x91821DE6, 0x17C9DDF1, 0xC688651C, 0xA9CD8C7F,
			0x456AE3C3, 0x39798E8E, 0xBA4E894B, 0x54EFB8F3,
			0x9EEE6CF2, 0xCF8BA4A0, 0xB804B11E, 0x1B01194E,
			0x29286191, 0xC82B8E3F, 0xA20EFDE9, 0x393B52CD,
			0x6A38A21C, 0x4173DAC1, 0xA93303DE, 0xD3109CF6,
			0x4D1E9143, 0x7E29B9E2, 0x92475DB0, 0x131E1845,
			0x71E968FE, 0x3A4659C0, 0xDF9CD5CB, 0x5C392768,
			0xDC8ABB26, 0x01D067EA, 0xB647F164, 0x4D552BBA,
			0xF939C661, 0x7B4494C7, 0xF5E2323E, 0x8CD60AE7,
			0x115FE119, 0x1B0C079B, 0x62CA3C3C, 0xFF9076A7,
			0x45CB8195, 0x2A9D4143, 0x06436292, 0xD5862573
		},
		.sce_type  = 0x9F2C9E07,
		.key_type  = 0x9EC6932F,
		.self_type = 0xEC0FE207,
		.key_rev   = 0xEE9B72FF,
		.flags     = 0x7F9E3986,
		.dbg_key_name = {
			0x2B, 0xB3, 0x3A, 0x41, 0x1F, 0xB8, 0x73, 0x36, 0x34, 0xE9, 0x22, 0x33, 0xF6, 0xCB, 0xDC, 0x8A,
			0x71, 0xAD, 0x3C, 0x17, 0x29, 0xE4, 0x88, 0xF8, 0x73, 0x4C, 0x94, 0x48, 0xED, 0x40, 0xDE, 0x4B,
			0xB2, 0x98, 0xFC, 0x42
		},
		.magic     = 0x11B5D6E0,
		.hash      = 0x27ED4F35
	},
	{
		.key = {
			0x33, 0xE9, 0x4B, 0xA9, 0xCF, 0xC3, 0xF0, 0xB9, 0xCF, 0x08, 0xA7, 0xE8, 0xEC, 0x2C, 0x28, 0xA6,
			0xA3, 0xB8, 0xB1, 0x81, 0x67, 0x4B, 0x0C, 0xA8, 0x3B, 0xAC, 0x23, 0x30, 0x82, 0x7B, 0x29, 0x56
		},
		.iv = {
			0x3D, 0x0B, 0x03, 0x8D, 0xF2, 0xCD, 0xDF, 0x14, 0x54, 0x4E, 0x70, 0x38, 0x7E, 0x12, 0x4E, 0x9A
		},
		.minver    = 0x514E4C424DC700EF,
		.maxver    = 0x28169D1321C53A0E,
		.rsa_n = {
			0xF38DC893, 0xB5A0A2AF, 0xED7ACA91, 0x10562059,
			0x77EBA1ED, 0x414481F1, 0xB27D60F0, 0xFB10FBCF,
			0xFD138C61, 0x30DB8959, 0x2EB14A69, 0x85B40011,
			0x0B628C95, 0xDDFABA5B, 0xA7107646, 0x0CE0437A,
			0xA08CD099, 0x9CEA0A91, 0xA44F7C74, 0xE248778C,
			0x456CD84E, 0x52956295, 0x59F5409C, 0x18CDF913,
			0x1CE57B53, 0x5D3D36B9, 0xE5DBECF7, 0x001669A1,
			0x1C80E51E, 0x9226F119, 0x5DADCA96, 0x7E8E0DD8,
			0x41DE5863, 0xCC85148F, 0x4FB51BC5, 0x396C1E27,
			0x97BD01BF, 0x0DC5F4BC, 0x55D7F768, 0x08B9F789,
			0x45E4B3C2, 0x42BB196B, 0xBF880A36, 0x5FDF7108,
			0x2674D484, 0xE4E39A6D, 0xC00F7A81, 0x7E31F77D,
			0x9F735AE2, 0xB0754609, 0x45CDA0CC, 0x845CF62B,
			0x6D0F0165, 0xA69C08F9, 0x279B87DC, 0x65F3FAD9,
			0xD829A561, 0xF5339652, 0x1D44342E, 0x56313643,
			0x35397622, 0x36A07D40, 0x70FC4510, 0xBD3F4FF0
		},
		.sce_type  = 0x73E293AE,
		.key_type  = 0x64605A87,
		.self_type = 0x386357AA,
		.key_rev   = 0x6A1D9104,
		.flags     = 0x5C73284C,
		.dbg_key_name = {
			0xE0, 0x77, 0x67, 0x01, 0xCA, 0x97, 0x19, 0x9B, 0xE5, 0x2F, 0x09, 0x39, 0xE5, 0x2A, 0xA1, 0x58,
			0x7B, 0xE1, 0xF8, 0x10, 0x4E, 0x1E, 0x51, 0x71, 0x2B, 0xA7, 0xD6, 0x95, 0x1D, 0xB4, 0x02, 0x91,
			0xA2, 0x10, 0xEB, 0xBB
		},
		.magic     = 0x973BBC32,
		.hash      = 0x90F54F41
	},
	{
		.key = {
			0xB3, 0xD8, 0xFF, 0x87, 0x31, 0x7A, 0xFC, 0xD6, 0xE4, 0x8F, 0x96, 0x57, 0x15, 0x5D, 0xA1, 0x0D,
			0x47, 0x61, 0xE9, 0x84, 0x34, 0x1E, 0x9F, 0x08, 0x63, 0xD9, 0xAF, 0x06, 0xF8, 0x20, 0xFE, 0x94
		},
		.iv = {
			0x02, 0xA6, 0xF7, 0xCD, 0xE2, 0xF9, 0xB0, 0x0C, 0x69, 0xBC, 0xFB, 0x95, 0x73, 0x5F, 0x25, 0x0A
		},
		.minver    = 0xC0419E8ECCDB5284,
		.maxver    = 0xAE0B7A0404EE66F6,
		.rsa_n = {
			0xEFF49811, 0xAF2C1721, 0x9DC562AD, 0x89D78D5F,
			0xD789C9C1, 0x0E0F150B, 0x13286D96, 0x3BF361C4,
			0xFBFD81E4, 0x6D8E60CC, 0xF3B1FA53, 0x46C6BE67,
			0x9F592CAD, 0x9D808294, 0xA2F2DC02, 0xA11C2CA9,
			0x06BE7738, 0x0DC9734A, 0x6721DE24, 0x6FB63C10,
			0xF80101CD, 0x0C2334AC, 0xB666F3A0, 0xF9CEF8C3,
			0x112F1790, 0xB3330D53, 0xC732200E, 0xBF18BC3F,
			0x57DB4F70, 0xA11E4C8E, 0xAF8371B8, 0xC6B836B7,
			0xFC55BF7D, 0x1F756498, 0x3E641848, 0xF6A13F53,
			0x7BEF187C, 0x2C511730, 0x8214455A, 0x816C142C,
			0xD1086B0A, 0xED7B3325, 0x8963AD1D, 0x29152166,
			0x745ACFA6, 0x87AAE9FD, 0x4677D279, 0xD67D86FA,
			0x3DB799D8, 0x37A9D089, 0x650B3BF6, 0x85B5E93E,
			0x67FBD461, 0x1EB1F171, 0x957C8689, 0x16A319AB,
			0xD2E6D278, 0xEB9A6BF5, 0x953199CA, 0xA17DFA2C,
			0xDE0E19B4, 0xDBBB325D, 0x22C8042C, 0xA317B470
		},
		.sce_type  = 0xFD4CA3B0,
		.key_type  = 0x0C99566E,
		.self_type = 0x0AB92134,
		.key_rev   = 0x8ADEAA0A,
		.flags     = 0x49FD35C2,
		.dbg_key_name = {
			0xF7, 0x53, 0x1C, 0x98, 0x06, 0xCE, 0x7D, 0x2F, 0x49, 0x0E, 0x27, 0x7D, 0xA0, 0xE1, 0x61, 0xD3,
			0x0A, 0x0E, 0x82, 0x5A, 0xF0, 0xF3, 0x23, 0x50, 0x3C, 0xC9, 0xA9, 0x38, 0x2D, 0xC5, 0x02, 0xA2,
			0x41, 0x57, 0x4D, 0xFA
		},
		.magic     = 0x7EB8F935,
		.hash      = 0x9DBBA9EE
	},
	{
		.key = {
			0x43, 0x7E, 0xFF, 0x5D, 0x5C, 0x01, 0xE8, 0x4F, 0x02, 0x88, 0xB1, 0xF6, 0xF5, 0x41, 0x7F, 0x37,
			0xD6, 0xED, 0x14, 0xC6, 0x87, 0x2C, 0x0C, 0x6C, 0xC4, 0x7F, 0xEE, 0xDE, 0x02, 0x0B, 0xBE, 0xCC
		},
		.iv = {
			0x7F, 0x80, 0x1E, 0x9D, 0x14, 0xC6, 0xB3, 0xB8, 0xD2, 0x46, 0x9D, 0x2A, 0x56, 0xC1, 0x69, 0xFA
		},
		.minver    = 0xC24DC1BE87A695DA,
		.maxver    = 0xE1E79C0A6675610A,
		.rsa_n = {
			0x931C8C30, 0x85B8D802, 0xFF4EFD71, 0xC96D8CEA,
			0x6368112E, 0xE0F08997, 0x3FA97B34, 0xFCCEF84E,
			0x5E0A30CF, 0xF051D6C6, 0x9CE89861, 0x713ACAC9,
			0xC942D8C6, 0x3399F2CC, 0x39AB5007, 0xDBF0AB15,
			0xAB11D2AC, 0xEA317870, 0xB67848A2, 0xD8E03DDC,
			0x46D4E87D, 0xF26FC68B, 0xDFFAA006, 0x7113E0AC,
			0x68FF2A44, 0x886150BF, 0xC0C143A6, 0xFB6A2043,
			0x9016B20F, 0x3FA90039, 0x4729CCC9, 0x8EF4A749,
			0xBE358493, 0x133292CC, 0xE5C1B430, 0x19D69621,
			0x9D6B32DD, 0xE92A0407, 0x6E4B4D70, 0xCD97D3D6,
			0x441D7DF4, 0x469D7233, 0x3E29C019, 0x12655B70,
			0xF9F88807, 0xC0D1BF46, 0xCAB8E843, 0xF6F3A624,
			0xE7A5E062, 0x183B7614, 0xB9106B10, 0xA5CC7B56,
			0x8634ADAC, 0x1FC2DEB3, 0x4B2C514D, 0xABE9D021,
			0xF8518EEF, 0x071BB6F0, 0xCAAA90E6, 0xBF5B0497,
			0xD598C196, 0xE9FC48DB, 0x807E6F43, 0x24134D28
		},
		.sce_type  = 0xE054C80B,
		.key_type  = 0x14574CD9,
		.self_type = 0x67405201,
		.key_rev   = 0xB6148914,
		.flags     = 0x20D3686C,
		.dbg_key_name = {
			0x43, 0x00, 0xCF, 0x64, 0x91, 0x04, 0xF0, 0x7E, 0x41, 0x93, 0x38, 0xA1, 0x98, 0xE2, 0xCB, 0xD4,
			0xED, 0x78, 0x39, 0x48, 0xE9, 0xBA, 0x76, 0x56, 0x0B, 0xDF, 0x78, 0xEB, 0x8C, 0x4D, 0xC4, 0xF1,
			0x08, 0x45, 0x98, 0xD9
		},
		.magic     = 0x3AE1B6FA,
		.hash      = 0x04B3F0EC
	},
	{
		.key = {
			0x64, 0xF6, 0x9D, 0x46, 0xEA, 0x5D, 0x30, 0xC8, 0x3C, 0xD3, 0x57, 0xEC, 0x63, 0x22, 0xD0, 0xCF,
			0x74, 0xE5, 0xAC, 0x35, 0x0A, 0x5F, 0xEA, 0x72, 0x71, 0xEE, 0xBF, 0xFD, 0x3A, 0x37, 0xF5, 0x33
		},
		.iv = {
			0xAE, 0x88, 0x21, 0x41, 0x44, 0xD6, 0x60, 0x0C, 0x2A, 0x1E, 0x81, 0x3A, 0xCF, 0xA3, 0x42, 0x49
		},
		.minver    = 0x1FE35A54536E7ED,
		.maxver    = 0xF799085813482BD8,
		.rsa_n = {
			0xC45670E0, 0xF7001D38, 0x49AD88D8, 0xDB4F06A9,
			0x79102876, 0xFB610F9D, 0x49F8605F, 0x6AC9116E,
			0xD56EE78F, 0x5E2A8482, 0x4EDF68CD, 0xBA3BFDDF,
			0xCAA72050, 0x25C15DEF, 0xE9EBED05, 0xBE72C41D,
			0x4ACB80A8, 0x4CE2A788, 0x9EEAE090, 0x17B9C569,
			0x38E9BD6B, 0x3F8F0931, 0x5B28D5A9, 0x4B4A95F6,
			0x8696A2EA, 0xD7FB2D95, 0xE2F6D226, 0x2F110BCC,
			0x6645D031, 0xA4CBE0BF, 0xC54C6E36, 0xFED0F27A,
			0x40D16DB2, 0xFA2EC20B, 0x5F0EEDB8, 0x0E3A74C0,
			0x803F3BC4, 0xC306896E, 0xA381500A, 0x352DE6A0,
			0xFF8DAF67, 0x08CF1CF7, 0xD052D66A, 0xBDA402E2,
			0x3626B704, 0xE11F0DFB, 0x07DF91CE, 0x419C5E48,
			0xE991CEF9, 0xAA26DB73, 0x69C5FB80, 0xC4E0A165,
			0x82EC9C84, 0x23050FA5, 0x1509D821, 0xF1218072,
			0x7D17988E, 0xA422E32A, 0x39BC00B7, 0xDF4095E0,
			0xABFC3AF6, 0x6FD76DDD, 0x550442AE, 0x90C7DC7A
		},
		.sce_type  = 0x97191640,
		.key_type  = 0xA1417352,
		.self_type = 0xFE690DE6,
		.key_rev   = 0x977E8FC2,
		.flags     = 0x6E349984,
		.dbg_key_name = {
			0xEC, 0xBC, 0x00, 0x79, 0x0D, 0x1C, 0x64, 0x81, 0x1B, 0x4D, 0x78, 0x5D, 0x65, 0xC4, 0xF8, 0x54,
			0xBC, 0x0D, 0x85, 0x41, 0x25, 0x01, 0xE6, 0x93, 0x3B, 0x09, 0x0D, 0xC4, 0xBF, 0x41, 0xA5, 0x93,
			0x7C, 0xD6, 0xA4, 0xD6
		},
		.magic     = 0xB4E5BB0C,
		.hash      = 0xC2C9DE18
	},
	{
		.key = {
			0x08, 0x78, 0x83, 0x1A, 0x29, 0xCF, 0xCA, 0x34, 0x97, 0x77, 0x28, 0xCD, 0x4D, 0x33, 0xD0, 0x78,
			0x3A, 0x70, 0x2C, 0xF7, 0xE3, 0xFD, 0xE8, 0x54, 0x98, 0x64, 0x87, 0xE4, 0x02, 0xA5, 0x14, 0xFC
		},
		.iv = {
			0x2B, 0xE9, 0xEB, 0x29, 0xF6, 0xAD, 0xB9, 0xA2, 0x5D, 0x42, 0xBD, 0x3B, 0xB2, 0xE6, 0x6C, 0xEC
		},
		.minver    = 0xC469DDA9B277591B,
		.maxver    = 0xFB36690B60C8BD19,
		.rsa_n = {
			0x55AE9227, 0x9EB31A07, 0x0CA62BD6, 0x13D5D930,
			0x3EDAE99B, 0xBA00B6F6, 0xB2514DB7, 0x169382C5,
			0x84E021AE, 0xBA753444, 0x66C35E88, 0x3ACEEB28,
			0x3E26398A, 0xAB9823B7, 0x2769AFDC, 0x6F26C3DB,
			0x96BEE095, 0xFC0718B6, 0x61AC1258, 0x764EDF0E,
			0x35F32ADF, 0x0C43321A, 0x2C09B7A4, 0x6A441DAC,
			0x624861BE, 0x53B49772, 0xADE4CB2D, 0x1CEF84ED,
			0x03729A52, 0x60F82122, 0xEFFF8D4A, 0x1AD8B36B,
			0x8234B5FA, 0x24C10A73, 0xCCA74771, 0x503B2B61,
			0xDE8EF298, 0x0DD70B80, 0x85894EA6, 0x6492C614,
			0x590AFAA1, 0x07CC4930, 0x11BF128D, 0xC5E869D0,
			0x59C41624, 0x4EA0E7F0, 0x707AC2A1, 0x307D1542,
			0xF512D668, 0x0632D464, 0xAACDDB9F, 0x0417A603,
			0x1721A7B2, 0x4E004BAC, 0x0BF70F7D, 0x4B32A9D6,
			0x136FF90F, 0x7FAC144B, 0xD2404B63, 0x986C271E,
			0xF6691131, 0xAFACC5D7, 0x26E52B6E, 0x93C7329E
		},
		.sce_type  = 0x4F26D6CE,
		.key_type  = 0x853D95F8,
		.self_type = 0xA48E1352,
		.key_rev   = 0x9E629B0D,
		.flags     = 0xC78B86BE,
		.dbg_key_name = {
			0xC6, 0xB3, 0x94, 0xB9, 0xF0, 0x13, 0xD7, 0x37, 0x4F, 0xCD, 0x26, 0x9D, 0x0C, 0x55, 0x76, 0xC5,
			0x57, 0xCB, 0x8F, 0xD2, 0xC7, 0xD3, 0x25, 0x58, 0xA3, 0x93, 0x72, 0x65, 0x5C, 0x09, 0xC2, 0xE8,
			0xF8, 0xEE, 0x38, 0x31
		},
		.magic     = 0xD8C70F24,
		.hash      = 0xD2982D50
	},
	{
		.key = {
			0xAE, 0x31, 0xBE, 0xCE, 0x5C, 0xD7, 0x02, 0x7B, 0x09, 0x1B, 0xAF, 0xFB, 0x10, 0xEB, 0x6A, 0x3F,
			0x7A, 0x6C, 0x63, 0xE4, 0x13, 0xC2, 0x98, 0xD4, 0xE5, 0xEF, 0x6B, 0xB4, 0xF0, 0x44, 0x06, 0x92
		},
		.iv = {
			0x0C, 0x60, 0x3F, 0xAC, 0x5F, 0x76, 0x56, 0xC3, 0xE9, 0xB1, 0xE9, 0xC6, 0xE2, 0x62, 0x11, 0xB4
		},
		.minver    = 0xE2FDE8A630DF23D7,
		.maxver    = 0x345AF6991D5A8D53,
		.rsa_n = {
			0x290CE57A, 0x71713E63, 0x6702503F, 0xE5E7246A,
			0x9047F832, 0xC08EB682, 0x1A28EE6A, 0x378890C3,
			0x51BEBA7E, 0x96E01C1A, 0xD29CD088, 0x8499F163,
			0x8FB99914, 0x17F9C648, 0xA77045D0, 0xBBE599BB,
			0xE006885C, 0x5BA8247A, 0x2AA83449, 0x5A80CEC3,
			0x448E191B, 0x1DFF0AEC, 0xB16909C3, 0x8F94AF5D,
			0x9008E62B, 0xA144E2AD, 0x99B2D55E, 0x509C8269,
			0xDE6C8143, 0xE3BADC36, 0xD980EAFE, 0xB7192EA0,
			0x1C617227, 0x8C9D225C, 0x53050F7B, 0xEC11D37F,
			0xACACA315, 0xFF33B801, 0x390FE16D, 0x6835CC57,
			0xB7D1B6BE, 0x02CF5E52, 0xC1F9FB11, 0x60ED78E0,
			0xF46DE489, 0x460785EB, 0x6D157C4A, 0x67E85EC9,
			0x2C03B7BF, 0x47CC63F5, 0x6AD3CFEA, 0x174FAA47,
			0xA726520B, 0xD16FBF13, 0x7835BA9F, 0x714FCAC2,
			0xCEB64F41, 0x2A2E9031, 0x3BC66DF0, 0x3EAC66A3,
			0x5451D6CF, 0xED5717F7, 0xD70C75BF, 0xE24C3A46
		},
		.sce_type  = 0xC6829659,
		.key_type  = 0x817B3A1C,
		.self_type = 0x80EFF158,
		.key_rev   = 0x6CF0E423,
		.flags     = 0xF0C00443,
		.dbg_key_name = {
			0x51, 0xD3, 0xDC, 0x1D, 0x6E, 0xBF, 0x99, 0x85, 0x55, 0xFF, 0x9D, 0x00, 0xF0, 0x0E, 0x5F, 0x45,
			0x11, 0x85, 0x25, 0xEB, 0x4D, 0x63, 0x5B, 0xD5, 0x5D, 0x42, 0x49, 0xC3, 0xA1, 0xCE, 0x5B, 0x85,
			0x8D, 0xF2, 0xBF, 0xF2
		},
		.magic     = 0x1374C75C,
		.hash      = 0x2B28B5D8
	},
	{
		.key = {
			0x6E, 0x2F, 0x69, 0x4C, 0x37, 0xB9, 0xAC, 0xB2, 0xAC, 0x89, 0xAB, 0x39, 0xFB, 0xDD, 0x39, 0x63,
			0x93, 0x0D, 0x5B, 0x8F, 0xEF, 0x50, 0x91, 0xAA, 0x2F, 0x71, 0x40, 0x9B, 0x97, 0xB6, 0xFF, 0x7C
		},
		.iv = {
			0x6D, 0xC8, 0x93, 0x0F, 0x02, 0x37, 0xF0, 0x4A, 0x9A, 0x60, 0xEC, 0xAF, 0x7F, 0x42, 0xFF, 0x32
		},
		.minver    = 0x14EFE0FF84579D6D,
		.maxver    = 0x4E77BB1C5A81FEE3,
		.rsa_n = {
			0x0B31A989, 0x77B5A002, 0x02CD0A0C, 0xC1ACCDC2,
			0x6DF8A631, 0x5CB0D18C, 0x1E3B13EC, 0x00AFB433,
			0x3C3B33D3, 0xFF0B5B70, 0x37FD52DC, 0xBEA94253,
			0x2BDA4C19, 0xA40CB6FE, 0x86A0F138, 0xBF9B3E5D,
			0x341AC3B9, 0x70E3C7AF, 0x8815C51D, 0x44BC9FB4,
			0xD6CDDFE2, 0x6F68E62B, 0xE38B4DCE, 0x7AD4F460,
			0xCA585AF4, 0x67299975, 0xEEC0157D, 0x03BDC8D8,
			0xECDD5ADD, 0xBBE9F7C7, 0xF705BA46, 0xDDD13810,
			0x33EF5638, 0x466D090A, 0xEF760398, 0x05BF8170,
			0xCA8C5DA4, 0xA59247D0, 0xBEC8EF15, 0xC9A220FF,
			0x745F4E4C, 0xC50ACC53, 0xF6AAB557, 0xD106DA82,
			0xB7B68234, 0x69D1913C, 0xCE3BCB5A, 0xBAA45A2A,
			0xC5835E8D, 0x74AA4F57, 0xD303915E, 0xE5622EF7,
			0xD18E2EF4, 0xFE408494, 0x1DA5E768, 0x762A41DD,
			0x5C465A51, 0xD78CFDF1, 0x98A072C0, 0x478CFE2D,
			0xF7C88FF8, 0xF1738BFD, 0xD4B5B582, 0x4291A993
		},
		.sce_type  = 0xA352A1C1,
		.key_type  = 0x60856693,
		.self_type = 0xF1FEB944,
		.key_rev   = 0xAE020FBD,
		.flags     = 0x383864AD,
		.dbg_key_name = {
			0x16, 0x5C, 0xCF, 0x07, 0xFD, 0xE1, 0x08, 0xF2, 0x48, 0x42, 0x82, 0xDC, 0x3C, 0xD0, 0x3F, 0x9A,
			0x58, 0x97, 0x9E, 0xCC, 0x67, 0x46, 0x53, 0xAC, 0xC1, 0x38, 0x45, 0x2A, 0xEA, 0x96, 0xA9, 0x3D,
			0xDD, 0xDA, 0x05, 0xBB
		},
		.magic     = 0x3D26553A,
		.hash      = 0x7BA1D7AA
	},
	{
		.key = {
			0x96, 0xD3, 0xD7, 0xF3, 0x4F, 0x7E, 0xAE, 0xE2, 0x35, 0x1B, 0x6E, 0x7B, 0xAD, 0xA7, 0xED, 0x5F,
			0xEC, 0xB2, 0x63, 0xFC, 0x27, 0xB4, 0xA0, 0x27, 0x1E, 0x1A, 0xDF, 0xFE, 0x4F, 0x9E, 0x39, 0xB9
		},
		.iv = {
			0x81, 0xAB, 0x58, 0x8C, 0xD6, 0x5D, 0x3D, 0x2F, 0xC7, 0x53, 0xA4, 0x8B, 0x7F, 0x66, 0x9E, 0x1E
		},
		.minver    = 0x6535E2040D6DADF,
		.maxver    = 0x385159120502A703,
		.rsa_n = {
			0x4836B185, 0xF1ABB108, 0x11D98512, 0x80A6C6DE,
			0xCAF8FEE5, 0xD3B3400E, 0xB2C9E9EF, 0xBE372BE6,
			0x97D3A4D4, 0x17C35D86, 0x0ED2728B, 0x1F099691,
			0x208FC4D7, 0x92CE8F09, 0xB1A18446, 0x8FAE93D7,
			0x058C9C5E, 0x322B62BC, 0xA32E2735, 0x1ED1A059,
			0x32DE407C, 0xB4D42C1E, 0x665C0E7A, 0xB0DFDB56,
			0x25E53D9A, 0xAA927D91, 0x879D542D, 0xC763EF41,
			0x2F935233, 0x80BE920A, 0x41FC6EFA, 0xA7BC7E55,
			0x866E7A1C, 0x001F84D7, 0xAE205608, 0x1EF47045,
			0xD830D73A, 0xD700D2F8, 0x1A61B017, 0x5C27B687,
			0x79721E31, 0x2A84E9C5, 0x23AFB768, 0x175D2F38,
			0x4AF6105D, 0xD332F6FE, 0x9DA9735B, 0x2710D93D,
			0x5CE07920, 0x083DCFC4, 0x9B4C954F, 0x1CAA2A08,
			0x0F3D4996, 0x0DD2321F, 0x0162AAF7, 0xB19E444A,
			0x946B5909, 0x5862BB16, 0x7B530A50, 0x368776F4,
			0x42583882, 0x76730051, 0x4F07D1EB, 0xA7749A62
		},
		.sce_type  = 0xC0586D95,
		.key_type  = 0x291C7082,
		.self_type = 0x1E48DA83,
		.key_rev   = 0x2D511593,
		.flags     = 0x317C1E31,
		.dbg_key_name = {
			0x0E, 0x07, 0x3B, 0x22, 0x90, 0xD5, 0x07, 0x97, 0x2B, 0xAE, 0x57, 0x53, 0x41, 0xCD, 0xB9, 0xFB,
			0xD2, 0x28, 0x22, 0x9B, 0xF3, 0xF1, 0xB3, 0xCD, 0x7D, 0x92, 0x5C, 0x4B, 0x58, 0x7B, 0x1F, 0xC6,
			0xD0, 0x49, 0x62, 0x5E
		},
		.magic     = 0xB1C1F795,
		.hash      = 0xE0B43CCE
	},
	{
		.key = {
			0x8F, 0xB8, 0xA1, 0x13, 0x09, 0xD1, 0x2F, 0x6F, 0x8C, 0x79, 0x1A, 0x41, 0x14, 0x20, 0x97, 0x33,
			0xED, 0xBB, 0x8C, 0xFF, 0x16, 0xB5, 0x02, 0xEB, 0x5A, 0x7D, 0xB6, 0x77, 0xAA, 0x84, 0xDB, 0x57
		},
		.iv = {
			0x8B, 0x4C, 0x17, 0xB1, 0xB4, 0x5C, 0xC7, 0xBD, 0x30, 0x1E, 0xC8, 0xBF, 0xB8, 0xA5, 0x0D, 0xA5
		},
		.minver    = 0xE36F20A0A0023650,
		.maxver    = 0x516524A50DA63725,
		.rsa_n = {
			0x77A6ED4F, 0x7EF933AC, 0xD12D2EB1, 0x3221858E,
			0x8F3C39D7, 0x02F3B1C9, 0x302F3D7F, 0xDC78130F,
			0xD6409832, 0x8B199534, 0x6FC7AA4D, 0xC2206AB7,
			0x7FB0062E, 0x888534C3, 0x2D2356E3, 0x420CC4DC,
			0xBAB2D29D, 0x13045056, 0xB98B6A1F, 0xC418E813,
			0x3AF528ED, 0xAEDEB6CB, 0x72DCFD75, 0xCC43F772,
			0xCB7E73A7, 0x043A60DE, 0x3B7D114D, 0xBE560A45,
			0xCE9D225A, 0xC1082578, 0xBACF2CE8, 0x152FF084,
			0xE406706E, 0x4FCF4FCA, 0x413B0DBF, 0x7A339976,
			0xDB74569E, 0x545A5DF3, 0xBAE6D296, 0x9492FFB4,
			0x89B766EA, 0x421D7B74, 0x88871855, 0xBE7CE51C,
			0x03E21DA4, 0x71F6DB95, 0x9FD416C0, 0x9CA221A6,
			0x26E79665, 0xCABFECF4, 0x95DBF717, 0x377398A4,
			0x98D2380E, 0x8A97074A, 0x21062D25, 0xC37A0565,
			0x8C7BE9C5, 0x17D75B3D, 0x43861FBA, 0x14A10687,
			0xC95CC92C, 0xE09901E3, 0xD58937D2, 0xEB98AF9F
		},
		.sce_type  = 0xDE336881,
		.key_type  = 0xDFDFA585,
		.self_type = 0x5FFB3AEC,
		.key_rev   = 0x675FD4A9,
		.flags     = 0xD3575179,
		.dbg_key_name = {
			0x8E, 0x10, 0x2C, 0xE3, 0x1F, 0xDF, 0x3A, 0x32, 0xF8, 0xA5, 0xCA, 0xE5, 0x6C, 0x98, 0x1C, 0x2C,
			0xBE, 0x7B, 0xA3, 0xDC, 0x22, 0x59, 0x37, 0x1C, 0xC8, 0xA9, 0xC4, 0xA3, 0xB6, 0xED, 0x4C, 0xEA,
			0x86, 0x40, 0xD5, 0x14
		},
		.magic     = 0x18B56E73,
		.hash      = 0x7EF6B4FA
	},
	{
		.key = {
			0xB7, 0x9E, 0x58, 0x36, 0x0F, 0x40, 0xE4, 0x20, 0xE7, 0x9D, 0xE3, 0x99, 0x24, 0xAE, 0x61, 0xBF,
			0x7B, 0x4C, 0x3E, 0x66, 0xA0, 0xB7, 0x9A, 0x13, 0xDB, 0x5C, 0x7C, 0x65, 0x0E, 0x60, 0xE4, 0xEA
		},
		.iv = {
			0x85, 0x2C, 0x70, 0xD8, 0x0F, 0x2C, 0xBB, 0x20, 0xA5, 0x6A, 0x74, 0x8E, 0x16, 0xA4, 0x4D, 0x21
		},
		.minver    = 0x9513B0FC14C1A90D,
		.maxver    = 0x41006494C34740BC,
		.rsa_n = {
			0xBF94087E, 0x99BDDCF0, 0x2EDACC23, 0xA02B5E63,
			0xFEF9C4ED, 0x200E6AB7, 0xCAFF9A92, 0xD9D1B54A,
			0x2A306CAF, 0xECC84D4D, 0xB7B15C39, 0x0992CE40,
			0x768D039B, 0x9B2702F3, 0xC4BC23A4, 0x55E4E07E,
			0x81C60559, 0xFB78C8A6, 0x55C4C314, 0x79EC0E28,
			0x3D8EAB9D, 0xD4B26265, 0xE8F880B7, 0x6435B670,
			0x43AC1C77, 0x6EF66FCF, 0x6825A874, 0x3123F2A5,
			0x5ECFED31, 0xE45B66E4, 0xC7417B49, 0xD1437245,
			0x242E87C3, 0x61FE110D, 0x25898BD3, 0xDD7FDDA5,
			0x6D61D000, 0xDC437B96, 0xC37D4F1A, 0xD4695A14,
			0xD8C5CDEC, 0x1813447C, 0x43754F78, 0x87840E4E,
			0xA9051D8E, 0x7B48B30E, 0xB5C461C2, 0x39B06EB7,
			0x995B6F5E, 0xE6D1425D, 0xCE8E30CC, 0xA1E032D3,
			0x2CCC3119, 0x1954FA0C, 0x3EEA806C, 0x03F03FE0,
			0x3252A560, 0x7C402E39, 0xDC3DDEC6, 0xB2C67483,
			0xA01B6CD8, 0x765D6FC1, 0x9A0C7AEE, 0x29360105
		},
		.sce_type  = 0xB15445E9,
		.key_type  = 0xC617E85B,
		.self_type = 0xFB74FCA2,
		.key_rev   = 0x9B541C3C,
		.flags     = 0x9F0EF53A,
		.dbg_key_name = {
			0x3C, 0x02, 0xCA, 0xC4, 0x7A, 0xC5, 0x61, 0x35, 0xBA, 0x35, 0x58, 0x45, 0x0F, 0x10, 0x37, 0x79,
			0x28, 0x9B, 0xC2, 0xAB, 0xB5, 0xF4, 0xB0, 0xA1, 0x9D, 0x8E, 0xE6, 0x69, 0x70, 0xC9, 0xE9, 0xF4,
			0x43, 0x36, 0x9A, 0x30
		},
		.magic     = 0x28EAD076,
		.hash      = 0x1B6B2D70
	},
	{
		.key = {
			0xEB, 0xD1, 0xBF, 0x02, 0xE7, 0xE6, 0x02, 0xE5, 0xD1, 0xC7, 0x04, 0x86, 0xF2, 0x43, 0x5A, 0x51,
			0x80, 0xB1, 0x23, 0x45, 0x92, 0x30, 0x19, 0x53, 0x72, 0x2F, 0x63, 0x9F, 0xA3, 0x62, 0x8D, 0xE1
		},
		.iv = {
			0xE5, 0xEC, 0xB6, 0x95, 0x0B, 0xAC, 0x46, 0x76, 0x3E, 0x02, 0xF6, 0xA5, 0x00, 0x45, 0x7F, 0xFB
		},
		.minver    = 0x9F41FB566D66BC83,
		.maxver    = 0xAFD63C95C83BC417,
		.rsa_n = {
			0xBE307C50, 0xC1CEE6A1, 0xC486BC7E, 0xB83EA070,
			0x6C44AB04, 0xF77748B4, 0x91B2DFF2, 0x02D5B6C4,
			0x6260AB63, 0x7250913B, 0xFDE78E9E, 0x288FB10A,
			0xA5245502, 0x8F154051, 0xF96D1BC6, 0x0665ACB9,
			0xFD8F8742, 0xD11B4BFF, 0x002C08E5, 0xCFAA7D57,
			0x1870C63C, 0x5CCB2483, 0x83137183, 0xBF2EF55A,
			0x4FD1817F, 0x81124C48, 0x8163ECA2, 0xBACECDA4,
			0xD3EBDED8, 0xE6EA9227, 0xB3323057, 0x22C178B7,
			0xC5904019, 0x232A9198, 0x51DFF3A3, 0x585C45CE,
			0x9FDA6EDC, 0xC5727DDE, 0x3BB4C1FC, 0x5A58102B,
			0xCF87B168, 0xAF9B6CC8, 0x481BE6CB, 0xE1A84DBF,
			0x6B55177C, 0x494E1712, 0xCD412B64, 0x2EB46CF2,
			0x25EFBCF0, 0xC99B7211, 0xF941B8E6, 0x94AA8987,
			0x162355B3, 0x3A8CFBBE, 0xE2E1BB92, 0x37D78ABB,
			0xABBB818C, 0x3EEB6288, 0x8ED75500, 0xCE219399,
			0x5D3C5C97, 0x765A454A, 0x41401106, 0x791FC7E6
		},
		.sce_type  = 0xFB911ED1,
		.key_type  = 0xCBFDD627,
		.self_type = 0x0F971B99,
		.key_rev   = 0x30E13BFE,
		.flags     = 0x908519C6,
		.dbg_key_name = {
			0x76, 0xFD, 0x69, 0xC6, 0x48, 0xD1, 0x07, 0xF2, 0x6B, 0x7C, 0xF7, 0x21, 0xE3, 0xF6, 0x33, 0xED,
			0x21, 0x66, 0x50, 0x4A, 0x67, 0x8C, 0xBC, 0x02, 0x40, 0x61, 0x98, 0xD2, 0xFA, 0xF3, 0x32, 0x31,
			0x24, 0xF9, 0x56, 0xB3
		},
		.magic     = 0xD3BCCB6B,
		.hash      = 0x0882CDB7
	},
	{
		.key = {
			0x74, 0xFD, 0x4A, 0xF5, 0x82, 0x48, 0x2C, 0x96, 0x66, 0xA6, 0x40, 0xF1, 0x14, 0x63, 0xB0, 0x86,
			0x8E, 0x42, 0x7A, 0x22, 0x88, 0xB7, 0x7E, 0x1F, 0x7E, 0x20, 0x88, 0x94, 0x94, 0xFD, 0xE7, 0xAA
		},
		.iv = {
			0x0E, 0x4D, 0x4E, 0x3A, 0xFB, 0xB2, 0xEF, 0xA3, 0x9C, 0x0B, 0x03, 0x10, 0x56, 0xDA, 0x17, 0xF5
		},
		.minver    = 0x723CFA410ABE6884,
		.maxver    = 0xF74C5A317F391FCD,
		.rsa_n = {
			0xE380064A, 0x60AD6A3E, 0x6C5D40EE, 0x5C1350E4,
			0x7278D456, 0xAD229FA8, 0xF840F658, 0x63CCF146,
			0x23071334, 0xDEC74191, 0x4473A88D, 0xAB91363E,
			0x8B763FBC, 0xF4FF207F, 0xBB3E88CB, 0x69AEA6F3,
			0x54788796, 0x47CA2EE4, 0x4279AB38, 0x1EFE2BDF,
			0xDFB26F31, 0x654BDAA0, 0x3FFCC96F, 0xA4B83B99,
			0xE4DF026B, 0xE1CD33CA, 0xF2A1ED93, 0x184AFDD9,
			0xC4275315, 0x81EB90DB, 0xC1A4EEEE, 0x77DC451B,
			0xB6B9F0BC, 0xCEE819AC, 0xF44369E9, 0x2FA06FAE,
			0x698204AA, 0xC8106C5B, 0x4FA3BA0E, 0x460812D4,
			0x6F5FD999, 0x164AF669, 0xE37B3C76, 0xD63780FA,
			0x201C2749, 0x3D960DB9, 0x10CA3B7D, 0x6883C658,
			0x65EE49D3, 0xF9FFA7A0, 0xDF05B711, 0xC401080F,
			0xFCFC43D7, 0x1E447420, 0x9FBB35B4, 0xC3E80CF1,
			0xD9ECCAA3, 0xCF49496A, 0x111F1B82, 0x56FC121D,
			0xD6339F7F, 0x220E73B2, 0xA1C0BA58, 0x7AE5809D
		},
		.sce_type  = 0x2F1D7A23,
		.key_type  = 0xDD3EA033,
		.self_type = 0x647B8E3E,
		.key_rev   = 0x6A3F11DE,
		.flags     = 0xFE6C3D4F,
		.dbg_key_name = {
			0x87, 0x58, 0x2F, 0x83, 0xC9, 0xEE, 0x4E, 0xA8, 0x2F, 0x74, 0x72, 0xAC, 0x4A, 0x3A, 0xED, 0x77,
			0x6B, 0x82, 0x65, 0xB5, 0x3E, 0xDA, 0xAC, 0x1C, 0x3B, 0xC5, 0x67, 0x87, 0x26, 0x80, 0x15, 0x5E,
			0x91, 0xBC, 0xD8, 0x46
		},
		.magic     = 0xCB802A35,
		.hash      = 0xF9793D07
	}
};
