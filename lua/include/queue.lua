local ffi = require "ffi"
ffi.cdef [[
]]

mod = {}
local mg_CQueue = {}
mod.mg_CQueue = mg_CQueue

function mg_CQueue:__serialize()
	return "require 'queue'; return " .. serpent.addMt(serpent.dumpRaw(self), "require('queue').mg_CQueue"), true
end

-- TODO: Add features:
--  => integrate RED
--  -> integrate watermark support
--  -> implement dropping policy based on watermarks?

function mod.createCQueue(args)
  args = args or {}
  args.size = args.size or 64
  args.multipleConsumers = args.multipleConsumers or false
  args.multipleProducers = args.multipleProducers or false
  args.socket = args.socket or select(2, dpdk.getCore())
  if(bit.and(args.size-1, args.size) != 0)then
    errorf("Queue size must be a power of two")
  end

  local flags = 0
  if(args.multipleConsumers == false) then
    flags = bit.bor(flags, 2)
  end
  if(args.multipleConsumers == false) then
    flags = bit.bor(flags, 1)
  end
  local ring = ffi.C.rte_ring_create("mg_ring", size, args.socket, flags)
  if(ring == nil)then
    errorf("ERROR creating ring")
    -- TODO: implement wrapper around rte_errno.h
    --  this will then also obsolete error.lua
  end


  return setmetatable({
    ring = ffi.gc(ring, function (self)
      print("I HAVE BEEN DESTRUCTED")
      ffi.C.rte_free(self)
    end ),
    size = args.size
  }, mg_CQueue)
end


function mg_CQueue:enqueue(object)
  return ffi.C.rte_ring_enqueue(self.ring, object)
end

function mg_CQueue:dequeue(object)
  local object = ffi.new("void *")
  local result = ffi.C.rte_ring_dequeue(self.ring, object)
  if (result == 0)then
    return object
  else
    return nil
  end
end


function mg_CQueue:enqueueMask(objects, bitmask)
  for i,v in ipairs(bitmask) do
    if v then
      self:enqueue(objects[i])
    end
  end
end
