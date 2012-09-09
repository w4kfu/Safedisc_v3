#include <idc.idc>

static decrypt_func_01()
{
	auto sub_addr = 0x66719F79;
	auto ref;
	auto push;
	auto key;
	auto addr;
	auto count;
	auto actual;

	for (ref = RfirstB(sub_addr); ref != BADADDR; ref = RnextB(sub_addr, ref))
	{
		for (push = FindCode(ref, SEARCH_UP | SEARCH_NEXT); ; push = FindCode(push, SEARCH_UP | SEARCH_NEXT))
		{
			if (GetMnem(push) == "push")
			{
				if (GetOpType(push, 0) == 5) // Immediate
				{
					Message("TYPE = %X, %X\n", GetOpType(push, 0), GetOperandValue(push, 0));
					addr = GetOperandValue(push, 0);
				}
				else if (GetOpType(push, 0) == 4) // FIX IT
				{
					
				}
			}
			break;
		}
		key = 0x522CFDD0;
		count = 0;
		while (1)
		{
			actual = Byte(addr);
			actual = actual ^ (key & 0xFF);
			addr = addr + 1;
			key = 0xA065432A - 0x22BC897F * key;
			if (!actual)
				break;
			Message("%c", actual);
			if (count != 127)
			{
				count++;
				//if (count < 0x80)
				continue;
			}
			break;
		}
		Message("\n");
	}
}

static main()
{
	decrypt_func_01();
}