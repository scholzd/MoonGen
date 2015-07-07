local ffi = require "ffi"
local serpent = require "Serpent"
local dpdk = require "dpdk"

ffi.cdef [[

// this struct definition will not work for actual use in lua,
// because preprocessor code was removed
struct rte_ring {
	char name[32];    /**< Name of the ring. */
	int flags;                       /**< Flags supplied at creation. */

	/** Ring producer status. */
	struct prod {
		uint32_t watermark;      /**< Maximum items before EDQUOT. */
		uint32_t sp_enqueue;     /**< True, if single producer. */
		uint32_t size;           /**< Size of ring. */
		uint32_t mask;           /**< Mask (size-1) of ring. */
		volatile uint32_t head;  /**< Producer head. */
		volatile uint32_t tail;  /**< Producer tail. */
	} prod;

	/** Ring consumer status. */
	struct cons {
		uint32_t sc_dequeue;     /**< True, if single consumer. */
		uint32_t size;           /**< Size of the ring. */
		uint32_t mask;           /**< Mask (size-1) of ring. */
		volatile uint32_t head;  /**< Consumer head. */
		volatile uint32_t tail;  /**< Consumer tail. */
	} cons;

	void * ring[0];
};



struct rte_ring *rte_ring_create(const char *name, unsigned count,
				 int socket_id, unsigned flags);

unsigned mg_queue_count_export(const struct rte_ring *r);
int mg_queue_dequeue_export(struct rte_ring *r, void **obj_p);
int mg_queue_enqueue_export(struct rte_ring *r, void *obj);
]]

-- XXX NOTE:
-- It is very hard to make a fast generic queue, which supports arbitary data
-- and blends in nicely in LUA.
-- This is because of the following reasons:
--  - It is not possible to transfer references to LUA objects, only ctype
--    objects can easily be transferred
--  - To transfer Lua objects some conversion is needed, which takes time
--  - Even for passing ctype objects, we lose all type information.
--  - To explicitly store type information with the reference costs extra
--    time + memory
-- Because of this, this is a relatively pure wrapper around rte_ring, which
-- only supports luaJIT ctype objects

mod = {}
local mg_CQueue = {}
mod.mg_CQueue = mg_CQueue
mg_CQueue.__index = mg_CQueue

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
  if(bit.band(args.size-1, args.size) ~= 0)then
    errorf("Queue size must be a power of two")
  end

  local flags = 0
  if(args.multipleConsumers == false) then
    flags = bit.bor(flags, 2)
  end
  if(args.multipleConsumers == false) then
    flags = bit.bor(flags, 1)
  end
  local ring = ffi.C.rte_ring_create("mg_ring", args.size, args.socket, flags)
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
  return ffi.C.mg_queue_enqueue_export(self.ring, object)
end

function mg_CQueue:dequeue(ctype)
  ctype = ctype or "struct rte_mbuf*"
  local object = ffi.new("void *")
  local objects = ffi.new("void*[1]")
  objects[0] = object
  local result = ffi.C.mg_queue_dequeue_export(self.ring, objects)
  if (result == 0)then
    return ffi.cast(ctype, objects[0])
  else
    return nil
  end
end

function mg_CQueue:dequeueMbuf()
  local object = ffi.new("void *")
  local objects = ffi.new("void*[1]")
  objects[0] = object
  local result = ffi.C.mg_queue_dequeue_export(self.ring, objects)
  if (result == 0)then
    return ffi.cast("struct rte_mbuf*", objects[0])
  else
    return nil
  end
end

function mg_CQueue:enqueueMbufsMask(objects, bitmask)
  for i,v in ipairs(bitmask) do
    if v then
      if (ffi.C.mg_queue_enqueue_export(self.ring, objects[i]) ~= 0)then
        printf("no enqueue possible")
        --objects[i]:free();
      end
      -- FIXME: if object is not enqueueable we have to somehow free it
      -- or notice the caller, that is has not been enqueued :(
      -- -> fixed this, but it only works for mbufs...
    end
  end
end

return mod
