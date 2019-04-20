def newheader(self, seq, err, typ, data, bank=False, multi=False):
	h = bytearray(7)
	h[0] = err << 5
	h[0] |= (seq >> 8) & 0x1f 
	print("hh", h[0])
	h[1] = seq & 0xff
	if typ == "comm":
		h[2] = _flag_ctx_comm
	elif typ == "peer":
		h[2] = _flag_ctx_peer
	elif typ == "tag":
		h[2] = _flag_ctx_tag
	elif typ == "content":
		h[2] = _flag_ctx_content
	if bank:
			h[2] |= 0x40
	if multi:
		h[2] |= 0x80
	(lenbytes) = struct.pack(">I", len(data)-7)
	i = 3
	for l in lenbytes:
		h[i] = l
			i+=1
	return h
