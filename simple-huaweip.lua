-- Define Huawei Portal Protocol
local p_huaweip = Proto("huaweip", "Huawei Protocol");

-- Define fields
-- field: version
local f_ver = ProtoField.uint8("huaweip.ver", "Version",base.HEX, {
		[0x02] = "Huawei 2",
	})

	
-- field: request/response type	
local action_val_map={
	[0x02] = "(2) Action2",
	[0x03] = "(3)REQ_AUTH",
	[0x04] = "(4)ACK_AUTH",
	[0x05] = "(5)REQ_LOGOUT",
	[0x07] = "(7)AFF_ACK_ATH",
	[0x08] = "(8)NTF_LOGOUT",
	[0x09] = "(9)REQ_INFO"

}
local f_type = ProtoField.uint8("huaweip.type", "type",base.HEX,action_val_map)

-- field: method
local f_method = ProtoField.uint8("huaweip.method", "method",base.HEX, {
		[0x01] = "PAP",
		[0x02] = "Method 2",
		[0x03] = "Method 3",
		[0x04] = "Method 4",
		[0x07] = "Method 7",
		[0x08] = "Method 8",

})


-- field: reserved
local f_Rsv = ProtoField.uint8("huaweip.Rsv", "Rsv",base.HEX, {
})

-- field: serial Number
local f_SerialNo = ProtoField.uint8("huaweip.SerialNo", "SerialNo",base.DEC)

-- field: request ID
local f_ReqID = ProtoField.uint8("huaweip.ReqID", "ReqID",base.DEC)
-- field: user IP
local f_UserIP = ProtoField.ipv4("huaweip.UserIP", "UserIP")

-- field: user port
local f_UserPort = ProtoField.uint8("huaweip.UserPort", "UserPort",base.DEC)

-- field: error code
local error_val_map={
	[-999]="系统繁忙，请稍候再试。system is busy, please try again later / Socket closed / Socket is closed/ Other Excption",
	[-2]="Request in Process. (double click filter)",
	[-1]="系统繁忙，请稍候再试。system is busy, please try again later",
	[0]="用户认证成功",
	[1]="用户认证请求被拒绝Authentication rejected",
	[2]="连接已建立Connection has been established",
	[3]="已有用户正在认证过程中，请稍后再试",
	[4]="认证失败Authentication failed",
	[5]="认证失败Authentication failed",
	[6]="认证失败Authentication failed",
	[7]="认证失败Authentication failed",
	
}
local f_ErrCode = ProtoField.int8("huaweip.ErrCode", "ErrCode",base.DEC,error_val_map)

-- field: attribute number
local f_AttrNum = ProtoField.uint8("huaweip.AttrNum", "AttrNum",base.DEC)

-- field: authenticator
local f_AuthenticatorOut = ProtoField.bytes("huaweip.AuthenticatorOut", "AuthenticatorOut")

-- field: attribute type
local attr_val_map={
		[0x01] = "UserName",
		[0x02] = "PassWord",
		[0x03] = "Challenge",
		[0x05] = "TextInfo",
		[0x06] = "Undefined",
		[0x07] = "Undefined",
		[0x08] = "Port",
		[0x0b] = "User_Mac",
		[0x0d] = "User_Private_IP",
		[0x40] = "WebAuthenInfo",
		[0xF1] = "User_IPV6",
}
local f_attrType=ProtoField.uint32("huaweip.attrType", "attrType",base.HEX,attr_val_map )

-- field: whole attribute
local f_attr=ProtoField.none("huaweip.attr", "attr",base.HEX)

-- field: length of the attribute
local f_attrLen=ProtoField.uint32("huaweip.attrLen", "attrLen",base.DEC)

-- field: hex content of attribute
local f_attrContent=ProtoField.uint32("huaweip.f_attrContent", "f_attrContent",base.HEX)

-- field: string content of attribute
local f_attrStringContent=ProtoField.string("huaweip.attrStringContent", "attrStringContent")

-- declare all fields for the huawei protocol
p_huaweip.fields = { f_ver, f_type,f_method,f_Rsv,f_SerialNo, f_ReqID,f_UserIP,f_UserPort,f_ErrCode,f_AttrNum,f_AuthenticatorOut,f_attr,f_attrType,f_attrLen,f_attrContent ,f_attrStringContent}

local data_dis = Dissector.get("data")

function p_huaweip.dissector(buf, pkt, tree)
		-- local action_val_map={
		-- [2] = "(2) Action2",
		-- [3] = "(3)REQ_AUTH",
		-- [4] = "(4)ACK_AUTH",
		-- [5] = "(5)REQ_LOGOUT",
		-- [7] = "(7)AFF_ACK_ATH",
		-- [8] = "(8)NTF_LOGOUT",
		-- [9] = "(9)REQ_INFO"
			-- }
	
		-- add attributes to tree
        local subtree = tree:add(p_huaweip, buf(0))
        subtree:add(f_ver, buf(0,1))
        subtree:add(f_type, buf(1,1))
		subtree:add(f_method, buf(2,1))
		subtree:add(f_Rsv, buf(3,1))
		
		subtree:add(f_SerialNo, buf(4,2))
		subtree:add(f_ReqID, buf(6,2))
		subtree:add(f_UserIP, buf(8,4))
		subtree:add(f_UserPort, buf(12,2))
		subtree:add(f_ErrCode, buf(14,1))
		subtree:add(f_AttrNum, buf(15,1))
		subtree:add(f_AuthenticatorOut, buf(16,16))
		
		-- subtree:add(f_method, buf(2,1))
		-- subtree:add(f_method, buf(2,1))
	
		local stringSwitch={
		[1] = "UserName",
		[2] = "PassWord",
		[5] = "TextInfo",
		}
		
		local macSwitch={
		[0x0b] = "User_Mac",
		}
		
        local attrNum = buf(15,1):uint()
		local pointer=32
		
		-- build tree for every attribute
		-- add every attribute to parent tree
		for i=1,attrNum do
			local attrType = buf(pointer,1)
			local attrLen=buf(pointer+1,1):uint()
			local attrTree=subtree:add(f_attr,buf(pointer,attrLen))
			
			attrTree:add(f_attrType,attrType )
			
			attrTree:add(f_attrLen,attrLen )
			local attrTypeForSwitch = buf(pointer,1):uint()
			
			
			local attrContent=buf(pointer+2,attrLen-2)
			
			if(stringSwitch[attrTypeForSwitch]) then
				attrTree:add(f_attrStringContent,attrContent )
			elseif (macSwitch[attrTypeForSwitch])then
				attrTree:add(f_attrStringContent,tostring( buf(pointer+2,attrLen-2):ether()))--tostring(attrContent:ether())
			else
				attrTree:add(f_attrContent,attrContent )--default
			end
			
			
			pointer=pointer+attrLen
			
		end
		
		--set info column as eg."(2) Action2 ...."
		if pkt.columns.info then
			pkt.columns.info:preppend(action_val_map[buf(1,1):uint()] .. " ")		
		end
		
		--set protocol column as "Huawei Protocol"
		if pkt.columns.protocol then
			pkt.columns.protocol:set("Huawei Protocol")
		end

end

-- grep the packet from udp port 2000 and 50100
local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(2000, p_huaweip)
udp_encap_table:add(50100, p_huaweip)
