-- LBI

local encrypted_bytecode = "XDI3XDc2XDExN1w5N1w4MVwwXDFcNFw4XDRcOFwwXDdcMFwwXDBcMFwwXDBcMFw2MFwxMDFcMTE4XDk3XDEwOFw2MlwwXDNcMFwwXDBcMTFcMFwwXDBcMFwwXDBcMlw0XDBcMFwwXDVcMFwwXDBcNjVcNjRcMFwwXDI4XDY0XDBcMVwzMFwwXDEyOFwwXDJcMFwwXDBcNFw2XDBcMFwwXDBcMFwwXDBcMTEyXDExNFwxMDVcMTEwXDExNlwwXDRcMTNcMFwwXDBcMFwwXDBcMFw3MlwxMDFcMTA4XDEwOFwxMTFcMzJcODdcMTExXDExNFwxMDhcMTAwXDMzXDBcMFwwXDBcMFw0XDBcMFwwXDdcMFwwXDBcN1wwXDBcMFw3XDBcMFwwXDExXDBcMFwwXDBcMFwwXDBcMFwwXDBcMA=="

--- Extract bits from an integer
--@author: Stravant
local function get_bits(input, n, n2)
	if n2 then
		local total = 0
		local digitn = 0
		for i = n, n2 do
			total = total + 2^digitn*get_bits(input, i)
			digitn = digitn + 1
		end
		return total
	else
		local pn = 2^(n-1)
		return (input % (pn + pn) >= pn) and 1 or 0
	end
end

local function decode_bytecode(bytecode)
	local index = 1
	local big_endian = false
    local int_size;
    local size_t;

    -- Actual binary decoding functions. Dependant on the bytecode.
    local get_int, get_size_t;

	-- Binary decoding helper functions
	local get_int8, get_int32, get_int64, get_float64, get_string;
	do
		function get_int8()
			local a = bytecode:byte(index, index);
			index = index + 1
			return a
		end
		function get_int32()
            local a, b, c, d = bytecode:byte(index, index + 3);
            index = index + 4;
            return d*16777216 + c*65536 + b*256 + a
        end
        function get_int64()
            local a = get_int32();
            local b = get_int32();
            return b*4294967296 + a;
        end
		function get_float64()
			local a = get_int32()
			local b = get_int32()
			return (-2*get_bits(b, 32)+1)*(2^(get_bits(b, 21, 31)-1023))*
			       ((get_bits(b, 1, 20)*(2^32) + a)/(2^52)+1)
		end
		function get_string(len)
			local str;
            if len then
	            str = bytecode:sub(index, index + len - 1);
	            index = index + len;
            else
                len = get_size_t();
	            if len == 0 then return; end
	            str = bytecode:sub(index, index + len - 1);
	            index = index + len;
            end
            return str;
        end
	end

	local function decode_chunk()
		local chunk;
		local instructions = {};
		local constants    = {};
		local prototypes   = {};
		local debug = {
			lines = {};
		};

		chunk = {
			instructions = instructions;
			constants    = constants;
			prototypes   = prototypes;
			debug = debug;
		};

		local num;

		chunk.name       = get_string();-- Function name
		chunk.first_line = get_int();	-- First line
		chunk.last_line  = get_int();	-- Last  line

        if chunk.name then chunk.name = chunk.name:sub(1, -2); end

		chunk.upvalues  = get_int8();
		chunk.arguments = get_int8();
		chunk.varg      = get_int8();
		chunk.stack     = get_int8();

                -- TODO: realign lists to 1
                -- Decode instructions
                do
                                for i = 1, get_int() do
                                        local instruction = { };

                                        local data = get_int32();
                                        local opcode = get_bits(data, 1, 6);
                                        instruction.opcode = opcode;

                                        instruction.A = get_bits(data, 7, 14);
                                        if (opcode == 1 or opcode == 5 or opcode == 7 or opcode == 36) then
                                                instruction.Bx = get_bits(data, 15, 32);
                                        else
                                                if (opcode == 22 or opcode == 31 or opcode == 32) then
                                                        instruction.sBx = get_bits(data, 15, 32) - 131071;
                                                else
                                                        instruction.B = get_bits(data, 24, 32);
                                                        instruction.C = get_bits(data, 15, 23);
                                                end
                                        end

                                        instructions[i] = instruction;
                                end
                end

		-- Decode constants
		do
			num = get_int();
			for i = 1, num do
				local constant = {
					-- type = constant type;
					-- data = constant data;
				};
				local type = get_int8();
				constant.type = type;

				if type == 1 then
					constant.data = (get_int8() ~= 0);
				elseif type == 3 then
					constant.data = get_float64();
				elseif type == 4 then
					constant.data = get_string():sub(1, -2);
				end

				constants[i-1] = constant;
			end
		end

		-- Decode Prototypes
		do
			num = get_int();
			for i = 1, num do
				prototypes[i-1] = decode_chunk();
			end
		end

		-- Decode debug info
        -- Not all of which is used yet.
		do
			-- line numbers
			local data = debug.lines
			num = get_int();
			for i = 1, num do
				data[i] = get_int32();
			end

			-- locals
			num = get_int();
			for i = 1, num do
				get_string():sub(1, -2);	-- local name
				get_int32();	-- local start PC
				get_int32();	-- local end   PC
			end

			-- upvalues
			num = get_int();
			for i = 1, num do
				get_string();	-- upvalue name
			end
		end

		return chunk;
	end

	-- Verify bytecode header
	do
		assert(get_string(4) == "\27Lua", "Lua bytecode expected.");
		assert(get_int8() == 0x51, "Only Lua 5.1 is supported.");
		get_int8(); 	-- Oficial bytecode
		big_endian = (get_int8() == 0);
        int_size = get_int8();
        size_t   = get_int8();

        if int_size == 4 then
            get_int = get_int32;
        elseif int_size == 8 then
            get_int = get_int64;
        else
	        -- TODO: refactor errors into table
            error("Unsupported bytecode target platform");
        end

        if size_t == 4 then
            get_size_t = get_int32;
        elseif size_t == 8 then
            get_size_t = get_int64;
        else
            error("Unsupported bytecode target platform");
        end

        assert(get_string(3) == "\4\8\0",
	           "Unsupported bytecode target platform");
	end

	return decode_chunk();
end

local function handle_return(...)
	local c = select("#", ...)
	local t = {...}
	return c, t
end

local function create_wrapper(cache, upvalues)
	local instructions = cache.instructions;
	local constants    = cache.constants;
	local prototypes   = cache.prototypes;

	local stack, top
	local environment
	local IP = 1;	-- instruction pointer
	local vararg, vararg_size

	local opcode_funcs = {
		[0]  = function(instruction)	-- MOVE
			stack[instruction.A] = stack[instruction.B];
		end,
		[1]  = function(instruction)	-- LOADK
			stack[instruction.A] = constants[instruction.Bx].data;
		end,
		[2]  = function(instruction)	-- LOADBOOL
			stack[instruction.A] = instruction.B ~= 0
			if instruction.C ~= 0 then
				IP = IP + 1
			end
		end,
		[3]  = function(instruction)	-- LOADNIL
			local stack = stack
			for i = instruction.A, instruction.B do
				stack[i] = nil
			end
		end,
		[4] = function(instruction)		-- GETUPVAL
			stack[instruction.A] = upvalues[instruction.B]
		end,
		[5]  = function(instruction)	-- GETGLOBAL
			local key = constants[instruction.Bx].data;
			stack[instruction.A] = environment[key];
		end,
		[6]  = function(instruction)	-- GETTABLE
			local C = instruction.C
			local stack = stack
			C = C > 255 and constants[C-256].data or stack[C]
			stack[instruction.A] = stack[instruction.B][C];
		end,
		[7]  = function(instruction)	-- SETGLOBAL
			local key = constants[instruction.Bx].data;
			environment[key] = stack[instruction.A];
		end,
		[8] = function (instruction)	-- SETUPVAL
			upvalues[instruction.B] = stack[instruction.A]
		end,
		[9] = function (instruction)	-- SETTABLE
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A][B] = C
		end,
		[10] = function (instruction)	-- NEWTABLE
			stack[instruction.A] = {}
		end,
		[11] = function (instruction)	-- SELF
			local A = instruction.A
			local B = instruction.B
			local C = instruction.C
			local stack = stack

			B = stack[B]
			C = C > 255 and constants[C-256].data or stack[C]

			stack[A+1] = B
			stack[A]   = B[C]
		end,
		[12] = function(instruction)	-- ADD
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B+C;
		end,
		[13] = function(instruction)	-- SUB
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B - C;
		end,
		[14] = function(instruction)	-- MUL
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B * C;
		end,
		[15] = function(instruction)	--DIV
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B / C;
		end,
		[16] = function(instruction) 	-- MOD
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B % C;
		end,
		[17] = function(instruction)	-- POW
			local B = instruction.B;
			local C = instruction.C;
			local stack, constants = stack, constants;

			B = B > 255 and constants[B-256].data or stack[B];
			C = C > 255 and constants[C-256].data or stack[C];

			stack[instruction.A] = B ^ C;
		end,
		[18] = function(instruction)	-- UNM
			stack[instruction.A] = -stack[instruction.B]
		end,
		[19] = function(instruction)	-- NOT
			stack[instruction.A] = not stack[instruction.B]
		end,
		[20] = function(instruction)	-- LEN
			stack[instruction.A] = #stack[instruction.B]
		end,
		[21] = function(instruction)	-- CONCAT
			local B = instruction.B
			local result = stack[B]
			for i = B+1, instruction.C do
				result = result .. stack[i]
			end
			stack[instruction.A] = result
		end,
		[22] = function(instruction)	-- JUMP
			IP = IP + instruction.sBx
		end,
		[23] = function(instruction)	-- EQ
			local A = instruction.A
			local B = instruction.B
			local C = instruction.C
			local stack, constants = stack, constants

			A = A ~= 0
			if (B > 255) then B = constants[B-256].data else B = stack[B] end
			if (C > 255) then C = constants[C-256].data else C = stack[C] end
			if (B == C) ~= A then
				IP = IP + 1
			end
		end,
		[24] = function(instruction)	-- LT
			local A = instruction.A
			local B = instruction.B
			local C = instruction.C
			local stack, constants = stack, constants

			A = A ~= 0
			B = B > 255 and constants[B-256].data or stack[B]
			C = C > 255 and constants[C-256].data or stack[C]
			if (B < C) ~= A then
				IP = IP + 1
			end
		end,
		[25] = function(instruction)	-- LT
			local A = instruction.A
			local B = instruction.B
			local C = instruction.C
			local stack, constants = stack, constants

			A = A ~= 0
			B = B > 255 and constants[B-256].data or stack[B]
			C = C > 255 and constants[C-256].data or stack[C]
			if (B <= C) ~= A then
				IP = IP + 1
			end
		end,
		[26] = function(instruction)	-- TEST
			local A = stack[instruction.A];
			if (not not A) == (instruction.C == 0) then
				IP = IP + 1
			end
		end,
		[27] = function(instruction)	-- TESTSET
			local stack = stack
			local B = stack[instruction.B]

			if (not not B) == (instruction.C == 0) then
				IP = IP + 1
			else
				stack[instruction.A] = B
			end
		end,
		[28] = function(instruction)	-- CALL
			local A = instruction.A;
			local B = instruction.B;
			local C = instruction.C;
			local stack = stack;
			local args, results;
			local limit, loop

			args = {};
			if B ~= 1 then
				if B ~= 0 then
					limit = A+B-1;
				else
					limit = top
				end

				loop = 0
				for i = A+1, limit do
					loop = loop + 1
					args[loop] = stack[i];
				end

				limit, results = handle_return(stack[A](unpack(args, 1, limit-A)))
			else
				limit, results = handle_return(stack[A]())
			end

			top = A - 1

			if C ~= 1 then
				if C ~= 0 then
					limit = A+C-2;
				else
					limit = limit+A
				end

				loop = 0;
				for i = A, limit do
					loop = loop + 1;
					stack[i] = results[loop];
				end
			end
		end,
		[29] = function (instruction)	-- TAILCALL
			local A = instruction.A;
			local B = instruction.B;
			local C = instruction.C;
			local stack = stack;
			local args, results;
			local top, limit, loop = top

			args = {};
			if B ~= 1 then
				if B ~= 0 then
					limit = A+B-1;
				else
					limit = top
				end

				loop = 0
				for i = A+1, limit do
					loop = loop + 1
					args[#args+1] = stack[i];
				end

				results = {stack[A](unpack(args, 1, limit-A))};
			else
				results = {stack[A]()};
			end

			return true, results
		end,
		[30] = function(instruction) -- RETURN
			--TODO: CLOSE
			local A = instruction.A;
			local B = instruction.B;
			local stack = stack;
			local limit;
			local loop, output;

			if B == 1 then
				return true;
			end
			if B == 0 then
				limit = top
			else
				limit = A + B - 2;
			end

			output = {};
			local loop = 0
			for i = A, limit do
				loop = loop + 1
				output[loop] = stack[i];
			end
			return true, output;
		end,
		[31] = function(instruction)	-- FORLOOP
			local A = instruction.A
			local stack = stack

			local step = stack[A+2]
			local index = stack[A] + step
			stack[A] = index

			if step > 0 then
				if index <= stack[A+1] then
					IP = IP + instruction.sBx
					stack[A+3] = index
				end
			else
				if index >= stack[A+1] then
					IP = IP + instruction.sBx
					stack[A+3] = index
				end
			end
		end,
		[32] = function(instruction)	-- FORPREP
			local A = instruction.A
			local stack = stack

			stack[A] = stack[A] - stack[A+2]
			IP = IP + instruction.sBx
		end,
		[33] = function(instruction)	-- TFORLOOP
			local A = instruction.A
			local B = instruction.B
			local C = instruction.C
			local stack = stack

			local offset = A+2
			local result = {stack[A](stack[A+1], stack[A+2])}
			for i = 1, C do
				stack[offset+i] = result[i]
			end

			if stack[A+3] ~= nil then
				stack[A+2] = stack[A+3]
			else
				IP = IP + 1
			end
		end,
		[34] = function(instruction)	-- SETLIST
			local A = instruction.A
			local B = instruction.B
			local C = instruction.C
			local stack = stack

			if C == 0 then
				error("NYI: extended SETLIST")
			else
				local offset = (C - 1) * 50
				local t = stack[A]

				if B == 0 then
					B = top
				end
				for i = 1, B do
					t[offset+i] = stack[A+i]
				end
			end
		end,
		[35] = function(instruction)	-- CLOSE
			io.stderr:write("NYI: CLOSE")
			io.stderr:flush()
		end,
		[36] = function(instruction)	-- CLOSURE
			local proto = prototypes[instruction.Bx]
			local instructions = instructions
			local stack = stack

			local indices = {}
			local new_upvals = setmetatable({},
				{
					__index = function(t, k)
						local upval = indices[k]
						return upval.segment[upval.offset]
					end,
					__newindex = function(t, k, v)
						local upval = indices[k]
						upval.segment[upval.offset] = v
					end
				}
			)
			for i = 1, proto.upvalues do
				local movement = instructions[IP]
				if movement.opcode == 0 then -- MOVE
					indices[i-1] = {segment = stack, offset = movement.B}
				elseif instructions[IP].opcode == 4 then -- GETUPVAL
					indices[i-1] = {segment = upvalues, offset = movement.B}
				end
				IP = IP + 1
			end

			local func = create_wrapper(proto, new_upvals)
			stack[instruction.A] = func
		end,
		[37] = function(instruction)	-- VARARG
			local A = instruction.A
			local B = instruction.B
			local stack, vararg = stack, vararg

			for i = A, A + (B > 0 and B - 1 or vararg_size) do
				stack[i] = vararg[i - A]
			end
		end,
	}

	local function loop()
		local instructions = instructions
		local instruction, a, b

		while true do
			instruction = instructions[IP];
			IP = IP + 1
			a, b = opcode_funcs[instruction.opcode](instruction);
			if a then
				return b;
			end
		end
	end

	local debugging = {
		get_stack = function()
			return stack;
		end;
		get_IP = function()
			return IP;
		end
	};

	local function func(...)
		local local_stack = {};
		local ghost_stack = {};

		top = -1
		stack = setmetatable(local_stack, {
			__index = ghost_stack;
			__newindex = function(t, k, v)
				if k > top and v then
					top = k
				end
				ghost_stack[k] = v
			end;
		})
		local args = {...};
		vararg = {}
		vararg_size = select("#", ...) - 1
		for i = 0, vararg_size do
			local_stack[i] = args[i+1];
			vararg[i] = args[i+1]
		end

		environment = getfenv();
		IP = 1;
		local thread = coroutine.create(loop)
		local a, b = coroutine.resume(thread)

		if a then
			if b then
				return unpack(b);
			end
			return;
		else
			if advanced_debug then
				--TODO advanced debugging
			else
				--TODO error converting
				local name = cache.name;
				local line = cache.debug.lines[IP];
				local err  = b:gsub("(.-:)", "");
				local output = "";

				output = output .. (name and name .. ":" or "");
				output = output .. (line and line .. ":" or "");
				output = output .. b
				--[[
				output = ("%s (Instruction=%s)"):format(output,
					lua_opcode_names[select(2,debug.getlocal(loop,1, 1)).opcode+1])
				--]]
				error(output, 0);
			end
		end
	end

	return func();
end

local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' -- You will need this for encoding/decoding
-- decoding
function dec(data)
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
            return string.char(c)
    end))
end


local function decrypt_bytecode(encrypted_bytecode)
        local decrypted_bytecode = ""
        decrypted_bytecode = dec(encrypted_bytecode)
        return decrypted_bytecode
end

local decrypted_bytecode = ""

decrypted_bytecode = decrypt_bytecode(encrypted_bytecode)

local function execute_decrypted_bytecode(decrypted_bytecode)
        local cache = decode_bytecode(decrypted_bytecode)
        return create_wrapper(cache)
end

local function Allow_Encryption(Non_Allowed_Encryption)
        local Allowed_Encryption = { }
        for v in string.gmatch(Non_Allowed_Encryption, "[^\\]+") do
                table.insert(Allowed_Encryption, string.char(v))
        end
        return table.concat(Allowed_Encryption)
end

return execute_decrypted_bytecode(Allow_Encryption(decrypted_bytecode))