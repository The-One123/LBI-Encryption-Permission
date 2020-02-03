-- Obfuscation

local script = function()

-- Script here vv

print("Hello World!")

-- Script here ^^

end

local function encrypt_bytecode(decrypted_bytecode)

end

local function convert_to_bytecode(non_bytecode)
        local bytecode = ""
        bytecode = string.sub(string.gsub(non_bytecode, ".", function(bytecode) return "\\" .. bytecode:byte() end), 0, -1)
        return bytecode
end

local function dump_function(non_dumped_function)
        local dumped = function() end
        dumped = string.dump(non_dumped_function)
        return dumped
end

local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' -- You will need this for encoding/decoding
-- encoding
function enc(data)
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

print(enc(convert_to_bytecode(dump_function(script))))
