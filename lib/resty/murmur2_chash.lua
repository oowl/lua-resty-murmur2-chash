local ffi = require "ffi"
local ffi_cast = ffi.cast
local C = ffi.C
local table = table

local ok, new_tab = pcall(require, "table.new")
if not ok or type(new_tab) ~= "function" then
    new_tab = function() return {} end
end


local DEFAULT_CHASH_RULE = "murmur2"

ffi.cdef[[
    typedef unsigned char u_char;
    uint32_t ngx_murmur_hash2(u_char *data, size_t len);
]]

local _M = {}
local mt = { __index = _M }

local function calc_hash(value)
    return tonumber(C.ngx_murmur_hash2(ffi_cast('uint8_t *', value), #value))
end

local function table_length(t)
    local len=0
    for k, v in pairs(t) do
      len=len+1
    end
    return len
end

function _M.new(nodes, args)
    if table.getn(nodes) == 0 then
        return nil, "empty nodes"
    end

    if not args then
        args = {}
    end

    local virtual_node_num = args.virtual_node_num or 1000
    local rule = args.rule or DEFAULT_CHASH_RULE
    local length = table.getn(nodes) * virtual_node_num

    local chash_arrays = new_tab(length, 0)
    local chash_maps = new_tab(0, length)
    local node_maps = new_tab(0, table.getn(nodes))

    for i = 1, table.getn(nodes) do
        local node = nodes[i]
        node_maps[node] = true
        for j = 1, virtual_node_num do
            local hash = calc_hash(node .. rule .. j)
            chash_maps[hash] = node
            table.insert(chash_arrays, hash)
        end
    end

    table.sort(chash_arrays)

    local self = {
        virtual_node_num = virtual_node_num,
        chash_arrays = chash_arrays,
        chash_maps = chash_maps,
        length = length,
        nodes = node_maps,
        rule = rule,
    }
    return setmetatable(self, mt)
end

local function find_chash_value(chash_arrays, len, hash_key)
    local left = 1
    local right = len
    local mid

    if hash_key < chash_arrays[left] or hash_key > chash_arrays[right] then
        return chash_arrays[left]
    end

    while left <= right do
        mid = math.floor((left + right) / 2)
        if chash_arrays[mid] == hash_key then
            return chash_arrays[mid]
        elseif chash_arrays[mid] < hash_key then
            left = mid + 1
        else
            right = mid - 1
        end
    end

    return chash_arrays[left]
end

function _M:get_node(key)
    local hash = calc_hash(key)
    local chash_value = find_chash_value(self.chash_arrays, self.length, hash)
    return self.chash_maps[chash_value]
end

function _M:add_node(node)
    if self.nodes[node] then
        return nil, "node already exists"
    end

    self.nodes[node] = true

    local virtual_node_num = self.virtual_node_num
    local rule = self.rule
    local length = table_length(self.nodes) * virtual_node_num

    local chash_arrays = new_tab(length, 0)
    local chash_maps = new_tab(0, length)

    for i = 1, table.getn(self.nodes) do
        local node = self.nodes[i]
        for j = 1, virtual_node_num do
            local hash = calc_hash(node .. rule .. j)
            chash_maps[hash] = node
            table.insert(chash_arrays, hash)
        end
    end

    table.sort(chash_arrays)

    self.chash_arrays = chash_arrays
    self.chash_maps = chash_maps
    self.length = length

    return true
end


function _M:delete_node(node)
    if not self.nodes[node] then
        return nil, "node not exists"
    end

    self.nodes[node] = nil

    local virtual_node_num = self.virtual_node_num
    local rule = self.rule
    local length = table_length(self.nodes) * virtual_node_num

    local chash_arrays = new_tab(length, 0)
    local chash_maps = new_tab(0, length)

    for i = 1, table_length(self.nodes) do
        local node = self.nodes[i]
        for j = 1, virtual_node_num do
            local hash = calc_hash(node .. rule .. j)
            chash_maps[hash] = node
            table.insert(chash_arrays, hash)
        end
    end

    table.sort(chash_arrays)

    self.chash_arrays = chash_arrays
    self.chash_maps = chash_maps
    self.length = length

    return true
end