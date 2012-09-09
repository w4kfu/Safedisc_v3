#include <idc.idc>

static decrypt_func_01(addr)
{
	auto key;
	auto count;
	auto actual;

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

static decrypt_func_01_parent()
{
	auto sub_addr = 0x66719F79;
	auto ref;
	auto push;
	auto addr;

	for (ref = RfirstB(sub_addr); ref != BADADDR; ref = RnextB(sub_addr, ref))
	{
		for (push = FindCode(ref, SEARCH_UP | SEARCH_NEXT); ; push = FindCode(push, SEARCH_UP | SEARCH_NEXT))
		{
			if (GetMnem(push) == "push")
			{
				addr = GetOperandValue(push, 0);
				if (GetOpType(push, 0) == 5) // Immediate
				{
					//Message("TYPE = %X, %X\n", GetOpType(push, 0), GetOperandValue(push, 0));
					decrypt_func_01(addr);
				}
				else if (GetOpType(push, 0) == 4) // FIX IT
				{
					// Get second parameter of the function
					auto sub_addr_push;
					auto ref2;
					auto push2;
					auto i;
					
					sub_addr_push = FirstFuncFchunk(push);
					for (ref2 = RfirstB(sub_addr_push); ref2 != BADADDR; ref2 = RnextB(sub_addr_push, ref2))
					{
						i = 0;
						for (push2 = FindCode(ref2, SEARCH_UP | SEARCH_NEXT); ; push2 = FindCode(push2, SEARCH_UP | SEARCH_NEXT))
						{
							if (GetMnem(push2) == "push")
							{
								i = i + 1;
								if (i == 2)
								{
									addr = GetOperandValue(push2, 0);
									//Message("GOOD PARAMETER = %X (0x%X) \n", addr, push2);
									decrypt_func_01(addr);
									break;
								}
							}
						}
					}
					//Message("TYPE = %X, %X\n", GetOpType(push, 0), FirstFuncFchunk(push));
				}
			}
			break;
		}
	}
}

static main()
{
	decrypt_func_01_parent();
}