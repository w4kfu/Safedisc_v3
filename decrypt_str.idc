#include <idc.idc>

static GetAddrStr(value)
{
	auto start = 0x18694D9;
	auto end = 0x1869758;
	auto i;

	while (value)
	{
		while (Byte(start) != 0 && start < end)
			start = start + 1;
		if (start >= end)
			return (0);
		start = start + 1;
		value = value - 1;
	}
	return (start);
}

static decrypt_str(ref, str, vale)
{
	auto val;
	
	Message("Decyph (ref = %08X ; val = %X) : ", ref, vale);
	Message("%c", Byte(str));
	val = Byte(str);
	str = str + 1;
	while (Byte(str) != 0)
	{
		val = val ^ (Byte(str) - 1);
		Message("%c", val);
		str = str + 1;
	}
	Message("\n");
}

static main()
{
	auto sub_addr = 0x01869470;
	auto ref;
	auto push;
	auto str;
	auto vale;
	
	for (ref = RfirstB(sub_addr); ref != BADADDR; ref = RnextB(sub_addr, ref))
	{
		for (push = FindCode(ref, SEARCH_UP | SEARCH_NEXT); ; push = FindCode(push, SEARCH_UP | SEARCH_NEXT))
		{
			if (GetMnem(push) == "push")
			{
				vale = GetOperandValue(push, 0);
				str = GetAddrStr(GetOperandValue(push, 0));
				if (str)
					decrypt_str(ref, str, vale);
				break;
			}
		}
	}
}