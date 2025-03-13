const fs = require("fs");
const path = require("path");
const net = require("net");
const crypto = require("crypto");
const chalk = require("chalk").default;
class TCPServerManager {
	constructor() {
		this.SERVER_IP = "0.0.0.0";
		this.SERVER_PORT = 7777;
		this.users = new Map(); // 儲存使用者資料
		this.maps = new Map(); // 儲存地圖上的使用者
		this.mapsInfo = {};
		this.USERS = {
			"20000001": {
				singleMD5: crypto.createHash("md5").update("Justina0228_99").digest("hex"),
				doubleMD5: crypto.createHash("md5").update(
					crypto.createHash("md5").update("Justina0228_99").digest("hex")
				).digest("hex")
			},
			"23097385": {
				singleMD5: crypto.createHash("md5").update("Justina0228_99").digest("hex"),
				doubleMD5: crypto.createHash("md5").update(
					crypto.createHash("md5").update("Justina0228_99").digest("hex")
				).digest("hex")
			}
		};
		this.userSessions = new Map();
		this.POLICY_XML = `
        <?xml version="1.0"?>
        <cross-domain-policy>
            <allow-access-from domain="*" to-ports="7777" />
        </cross-domain-policy>\0`;
		this.loadMapsInfo();
		this.startServer();
	}
	startServer() {
		this.server = net.createServer((socket) => this.handleConnection(socket));
		this.server.listen(this.SERVER_PORT, this.SERVER_IP, () => {
			this.log("INFO", `TCP Server 啟動 ${this.SERVER_IP}:${this.SERVER_PORT}`);
		});
	}
	handleConnection(socket) {
		this.log("INFO", `連線成功： ${socket.remoteAddress}:${socket.remotePort}`);
		const savedSession = this.userSessions.get(socket.remoteAddress);
		if (savedSession) {
			socket.userID = savedSession.userID;
			this.log("INFO", `恢復已登入使用者: ${socket.userID}`);
		}
		socket.setEncoding(null);
		socket.on("data", (data) => this.handleData(socket, data));
		socket.on("error", (err) => this.log("ERROR", `連線錯誤： ${err.message}`));
		socket.on("close", () => {
			this.log("INFO", `斷開連線： ${socket.remoteAddress}:${socket.remotePort}`);
		});
	}
	/*** 載入地圖列表 ***/
	loadMapsInfo() {
		const filePath = path.join(__dirname, 'mapsInfo.json');
		try {
			const data = fs.readFileSync(filePath, 'utf8');
			this.mapsInfo = JSON.parse(data);
			this.log("INFO", '地圖資訊載入成功');
		} catch (error) {
			this.log("ERROR", '地圖資訊載入失敗');
		}
	}
	/*** 自訂Log ***/
	log(type, message) {
		const colors = {
			INFO: chalk.blue,
			ERROR: chalk.red,
			ACTION: chalk.green,
			RESPONSE: chalk.cyan,
			PACKET: chalk.magenta,
			"FETCH CROSS": chalk.yellow,
			CmdID: chalk.white
		};
		const colorFn = colors[type] || ((msg) => msg);
		console.log(colorFn(`[${type}] ${message}`));
	}
	handleData(socket, data) {
		console.log(data);
		// if (!data.includes('CmdID:201') && data.includes('CmdID')) return;
		if (!Buffer.isBuffer(data)) data = Buffer.from(data);
		this.log("PACKET", data.toString("hex"));
		if (data.toString().includes("<policy-file-request/>")) {
			this.log("ACTION", "請求 Cross Policy");
			socket.write(this.POLICY_XML);
			socket.end();
			return;
		}
		if (data.length < 9) {
			this.log("ERROR", "封包長度不足，丟棄封包");
			return;
		}
		let userID = '', commandID = '';
		const version = data.readUInt8(4);
		if (data.length >= 11) {
			commandID = data.readUInt32BE(7) > 30000 ? data.readUInt16BE(7) : data.readUInt32BE(7);
		}
		if (data.length >= 15) {
			userID = this.USERS[data.readUInt32BE(11)] ? data.readUInt32BE(11) : data.readUInt32BE(9);
		}
		// try {
		// console.log("[PACKET DATA DUMP]");
		// for (let i = 0; i <= 17; i++) {
		// console.log(`readUInt8 ${i}: ${data.readUInt8(i)}`);
		// console.log(`readUInt16BE ${i}: ${data.readUInt16BE(i)}`);
		// console.log(`readUInt32BE ${i}: ${data.readUInt32BE(i)}`);


		// if (data.readUInt32BE(i) == commandID) {
		// 	console.log(`readUInt32BE ${i}: ${data.readUInt32BE(i)}`);
		// }
		// if (data.readUInt32BE(i) == userID) {
		// 	console.log(`readUInt32BE ${i}: ${data.readUInt32BE(i)}`);
		// }
		// if (data.readUInt8(i) == commandID) {
		// 	console.log(`readUInt8 ${i}: ${data.readUInt8(i)}`);
		// }
		// if (data.readUInt8(i) == userID) {
		// 	console.log(`readUInt8 ${i}: ${data.readUInt8(i)}`);
		// }
		// }
		// } catch (err) {
		// console.log("[ERROR] 讀取封包時發生錯誤: " + err.message);
		// }

		// const result = data.readUInt32BE(16);
		const result = null;
		const packetLength = data.readUInt32BE(0);
		let body = Buffer.alloc(0);
		if (packetLength > 17) {
			body = data.slice(17, packetLength);
		}
		if (!this.USERS[userID]) return;
		this.log("DEBUG", body.toString("hex"));
		this.log("DEBUG", `[PACKET INFO] 長度: ${packetLength}, 版本: ${version}, CmdID: ${commandID}, 使用者ID: ${userID}, 結果: ${result}`);
		const commandHandlers = {
			101: (socket) => this.handleAuthCode(socket), // loginDirSer
			103: (socket, userID, data) => this.handleLogin(data, socket), // getSerListByPage
			105: (socket) => socket.userID && this.handleServerList(socket, true), // NEW_RECOMMEND_SERVER_LIST
			106: (socket) => socket.userID && this.handleServerList(socket, false), // NEW_RANGE_SERVER_LIST
			201: (socket, userID, data) => this.handleLoginOnlineServer(socket, userID, data), // 登錄Online Server
			216: (socket, userID) => this.handleSMCTaskList(socket, userID), // SMC任務列表
			228: (socket, userID) => this.handlePetTaskList(socket, userID), // 拉取寵物任務列表
			232: (socket, userID) => this.handleSuperLamuCheck(socket, userID), // 查詢是否已有超級拉姆
			233: (socket, userID) => this.handlePetCountInMap(socket, userID), // 拉寵物在地圖中的數量
			239: (socket, userID, data) => this.handlePetGoHome(socket, userID, data), // 寵物回家
			302: (socket, userID, data) => this.handleChatMessage(socket, userID, data), // 聊天資訊
			303: (socket, userID, data) => this.handleWalk(socket, userID, data), // 走路
			305: (socket, userID, data) => this.handleUserAction(socket, userID, data), // 動作
			401: (socket, userID, data) => this.handleEnterMap(socket, userID, data), // 進入地圖
			402: (socket, userID, data) => this.handleLeaveMap(socket, userID, data), // 離開地圖
			405: (socket, userID, data) => this.handleAllSceneUser(socket, userID, data), // 場景用戶資訊
			406: (socket, userID, data) => this.handleGetMapInfo(socket, userID, data), // 獲取地圖資訊
			426: (socket, userID) => this.handleGetLoginSession(socket, userID), // 根據遊戲ID獲得登入簽登入Session
			507: (socket, userID, data) => this.handleViewInventory(socket, userID, data), // 查看背包
			609: (socket, userID) => this.handleBlacklist(socket, userID), // 獲得黑名單列表
			805: (socket, userID) => this.handleUnreadPostcardCount(socket, userID), // 僅讀取未讀過的明信片數目
			1328: (socket, userID) => this.handleGetMyProfession(socket, userID), // 獲取我的職業
			1496: (socket, userID) => this.handleMagicCourseQuery(socket, userID), // 查詢魔法課程
			2008: (socket, userID) => this.handleCommitteePresidentVote(socket, userID), // 屋委會會長投票
			3106: (socket, userID, data) => this.handleQueryNpcTasks(socket, userID, data), // 查詢NPC所有任務狀態
			6024: (socket, userID) => this.handleLoginStreak30Days(socket, userID), // 連續登錄資訊
			6026: (socket, userID) => this.handleLoginStreakSummary(socket, userID), // 查看連續30天登錄資訊
			6034: (socket, userID) => this.handlePlatformMessageStats(socket, userID), // 統計平台消息
			8606: (socket, userID, data) => this.handleQueryRewardStatus(socket, userID, data), // 查詢領取狀態
			8755: (socket, userID, data) => this.handleComeBackStatus(socket, userID, data), // COME_BK_STATUS
			8817: (socket, userID) => this.handleGetMiniGameStep(socket, userID), // 查看小遊戲步驟
			8920: (socket, userID) => this.handlePaymentPasswordRequirement(socket, userID), // GET_PAY_PWD_STATE
			8974: (socket, userID) => this.handleGetKnightTransferState8974(socket, userID), // GET_KNIGHT_TRANSFER_STATE
			8990: (socket, userID) => this.handleElementKnightInfo(socket, userID), // ELEMENT_KNIGHT_INFO
			9124: (socket, userID) => this.handleGetKnightTransferState(socket, userID), // getKnightTransferState
			10011: (socket, userID, data) => this.handleTimeGreeting(socket, userID, data), // 時間問候
			10101: (socket, userID, data) => this.handleIsFinishedSth(socket, userID, data), // 請求是否完成某件事
			10301: (socket, userID) => this.handleGetServerTime(socket, userID), // 獲取系統時間
			10302: (socket, userID) => this.handleRegistrationRedirectSession(socket, userID), /// 注冊會員跳轉頁面session
			11009: (socket, userID, data) => this.handleGetLimitInfo(socket, userID, data), // 通用狀態標記
			11010: (socket, userID) => this.handleInitPlayerEx(socket, userID), // CLI_PROTO_INIT_PLAYER_EX
			11085: (socket, userID, data) => this.handleGetUserInfo(socket, userID, data), // ID_11085
			12004: (socket, userID) => this.handleMagicSpiritUserInfo(socket, userID), // MAGICSPIRIT_USER_INFO
			12018: (socket, userID) => this.handleMagicSpiritBagInfo(socket, userID) // MAGICSPIRIT_BAG_INFO
		};
		if (commandHandlers[commandID]) {
			commandHandlers[commandID](socket, userID, data);
		} else {
			this.log("ERROR", `無效的 CmdID: ${commandID}，忽略封包`);
		}
	}
	handleLogin(data, socket) {
		this.log("ACTION", "登入帳號");
		let offset = 9;
		const userID = data.readUInt32BE(offset).toString();
		offset += 4;
		const passwordBuffer = data.subarray(offset, offset + 40);
		let password = passwordBuffer.toString("utf-8").replace(/\0/g, "").trim();
		password = password.match(/[a-f0-9]{32}/i)?.[0]?.toLowerCase() || "";
		const success = this.USERS[userID]?.doubleMD5 === password || this.USERS[userID]?.singleMD5 === password;
		const statusCode = success ? 0 : 5003;
		const packetLength = success ? 51 : 35;
		const response = Buffer.alloc(packetLength);
		this.log("INFO", `帳號：${userID}，密碼：${password}，登入狀態：${success}，Code：${statusCode}，packetLength：${packetLength}`);
		response.writeUInt32BE(packetLength, 0); // 總長度
		response.writeUInt8(1, 4); // 版本號
		response.writeUInt32BE(103, 5); // CmdID
		response.writeUInt32BE(parseInt(userID), 9); // 帳號
		response.writeUInt32BE(statusCode, 13);
		if (success) {
			response.writeUInt32BE(0, 17); // flag
			crypto.randomBytes(16).copy(response, 21); // Session Key
			socket.userID = userID;
			this.userSessions.set(socket.remoteAddress, { userID });
		} else {
			Buffer.from("Login Failed   ", "utf-8").copy(response, 17, 0, 14);
			response.writeUInt8(0, 31);
		}
		const hexResponse = response.toString('hex').toUpperCase();
		socket.write(response);
		this.log("RESPONSE", `發送登入${success ? "成功" : "失敗"}封包`);
	}
	handleServerList(socket, isGoodServerList = false) {
		this.log("ACTION", `發送${isGoodServerList ? "推薦" : "全部"}伺服器列表`);
		const servers = [
			{ id: 1, userCount: 0, ip: "35.221.224.190", port: 7777, friends: 0 },
			{ id: 2, userCount: 1, ip: "35.221.224.190", port: 7777, friends: 0 },
			{ id: 3, userCount: 20, ip: "35.221.224.190", port: 7777, friends: 0 },
		];
		const serverEntrySize = 30;
		const headerSize = 17;
		const serverCount = servers.length;
		const baseBodySize = 4 + serverCount * serverEntrySize; // 伺服器數量 + 各伺服器資訊
		const extraMetadataSize = isGoodServerList ? 12 : 0; // 只有推薦伺服器列表需要附加 12 Byte Metadata
		const packetLength = headerSize + baseBodySize + extraMetadataSize;
		this.log("INFO", `封包長度: ${packetLength}, 伺服器數量: ${serverCount}`);
		const response = Buffer.alloc(packetLength);
		let offset = 0;
		response.writeUInt32BE(packetLength, offset); offset += 4;
		response.writeUInt8(1, offset); offset += 1;  // 版本
		response.writeUInt32BE(isGoodServerList ? 105 : 106, offset); offset += 4;
		response.writeUInt32BE(socket.userID, offset); offset += 4; // userID
		response.writeUInt32BE(0, offset); offset += 4; // errorID
		response.writeUInt32BE(serverCount, offset); offset += 4; // 伺服器數量
		servers.forEach(server => {
			response.writeUInt32BE(server.id, offset); offset += 4;
			response.writeUInt32BE(server.userCount || 0, offset); offset += 4;
			const ipBuffer = Buffer.alloc(16, 0);
			Buffer.from(server.ip, "utf8").copy(ipBuffer, 0);
			ipBuffer.copy(response, offset);
			offset += 16;
			response.writeUInt16BE(server.port || 0, offset); offset += 2;
			response.writeUInt32BE(server.friends || 0, offset); offset += 4;
		});
		if (isGoodServerList) {
			response.writeUInt32BE(20, offset); offset += 4; // MaxServerID
			response.writeUInt32BE(0, offset); offset += 4;  // isVIP 
			response.writeUInt32BE(0, offset); offset += 4;  // 好友數量 
		}
		if (offset !== packetLength) {
			this.log("ERROR", `最終封包長度不匹配，應該是 ${packetLength}, 但實際是 ${offset}`);
			return;
		}
		socket.write(response);
		this.log("RESPONSE", `發送${isGoodServerList ? "推薦" : ""}伺服器列表封包`);
	}
	handleLoginOnlineServer(socket, userID, data) {
		this.log("ACTION", `處理登入 Online Server (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 25) {
			this.log("ERROR", `封包長度不足，無法讀取登入資訊`);
			return;
		}
		const serverID = data.readUInt16BE(offset + 1);
		const magicString = data.toString("utf8", offset + 3, offset + 18).replace(/\0/g, "");
		const sessionLen = data.readUInt32BE(offset + 19);
		const session = data.toString("utf8", offset + 23, offset + 23 + sessionLen).replace(/\0/g, "");
		const loginType = data.readUInt16BE(offset + 23 + sessionLen + 1);
		const adByte = data.readUInt8(offset + 23 + sessionLen + 3);
		this.log("INFO", `登入 Online Server:
			ServerID: ${serverID}
			MagicString: ${magicString}
			Session: ${session}
			LoginType: ${loginType}`);
		this.processLoginOnlineServer(socket, userID, serverID, magicString, session, loginType);
	}
	processLoginOnlineServer(socket, userID, serverID, magicString, session, loginType) {
		const user = {
			socket,
			userID, // 帳號
			serverID, // 登入的伺服器ID
			magicString, // ?
			session, // Session
			loginType, // 登入類型
			nick: `小鼴鼠${userID}`, // 暱稱
			color: 16766720, // 膚色
			vip: false, // 超級拉姆 (無:false/有:true)
			birthday: Math.floor(Date.now() / 1000), // 生日
			exp: 0, // 經驗值
			strong: 0, // 力量值
			iq: 0, // 智慧值
			charm: 0, // 魅力值
			game_king: 0, // ?
			molebean: 0, // 摩爾豆
			map: 3, // 目前所在地圖
			status: 0, // 狀態 (不知道幹嘛的，應該是帳號禁用狀態)
			action: 0, // 動作
			direction: 0, // 角色方向
			x: 333, // 角色位置x
			y: 333, // 角色位置y
			pet_action: 0, // 寵物動作
			grid: 0, // 格數
			action2: 0, // ? 
			super_guide: 0, // 超級嚮導
		};
		this.users.set(userID, user);
		this.enterMap(user, 3, 0);
		this.sendLoginOnlineSre(user);
		this.sendTextNotice(user, `文字測試${userID}`);
		this.broadcastChat(user, 0, "我是小摩爾");
		this.log("INFO", `使用者 ${userID} 成功登入 Online Server`);
	}
	sendLoginOnlineSre(user) {
		const body = this.makeLoginOnlineSre(user);
		const head = this.makeHead(201, user.userID, 0, body.length);
		user.socket.write(head);
		user.socket.write(body);
		this.log("RESPONSE", `發送登入 Online Server 回應 (UserID: ${user.userID})`);
	}
	makeLoginOnlineSre(user) {
		return this.makePrivateUserInfo(user);
	}
	makePrivateUserInfo(user) {
		const buffer = Buffer.alloc(218);
		buffer.writeUInt32BE(user.userID, 0);
		buffer.write(user.nick.padEnd(16, "\0"), 4, 16, "utf8");
		buffer.writeUInt32BE(0, 20); // Parent ID
		buffer.writeUInt32BE(0, 24); // Child count
		buffer.writeUInt32BE(0, 28); // New child count
		buffer.writeUInt32BE(user.color, 32);
		buffer.writeUInt32BE(user.vip ? 1 : 0, 36);
		buffer.writeUInt32BE(0, 40); // RoleType
		buffer.writeUInt32BE(user.birthday, 44);
		buffer.writeUInt32BE(user.exp, 48);
		buffer.writeUInt32BE(user.strong, 52);
		buffer.writeUInt32BE(user.iq, 56);
		buffer.writeUInt32BE(user.charm, 60);
		buffer.writeUInt32BE(user.game_king, 64);
		buffer.writeUInt32BE(user.molebean, 68);
		buffer.writeUInt32BE(user.map, 96);
		buffer.writeUInt32BE(0, 100); // Map Type
		buffer.writeUInt8(user.status, 104);
		buffer.writeUInt32BE(user.action, 106);
		buffer.writeUInt8(user.direction, 109);
		buffer.writeUInt32BE(user.x, 110);
		buffer.writeUInt32BE(user.y, 114);
		buffer.writeUInt32BE(509, 118); // LoginTimes
		buffer.writeUInt32BE(50601600, 122); // Birthday
		buffer.writeUInt32BE(0, 126); // PetSkill5_Flag
		buffer.writeUInt32BE(0, 130); // Magic_task
		buffer.writeUInt32BE(0, 134); // Vip_level
		buffer.writeUInt32BE(0, 138); // Vip_month
		buffer.writeUInt32BE(0, 142); // VipValue
		buffer.writeUInt32BE(0, 146); // VipEndTime
		buffer.writeUInt32BE(0, 150); // autoPayVip
		buffer.writeUInt32BE(0, 154); // Dragon ID
		return buffer;
	}
	sendTextNotice(user, message) {
		const messageBuffer = Buffer.from(message, "utf8");
		const bodyLength = 52 + messageBuffer.length;
		const buffer = Buffer.alloc(bodyLength);
		buffer.writeUInt32BE(10003, 0);
		buffer.writeUInt32BE(user.userID, 4);
		buffer.writeUInt32BE(0, 8); // Type
		buffer.writeUInt32BE(user.map, 12);
		buffer.writeUInt32BE(0, 16); // Map Type
		buffer.writeUInt32BE(0, 20); // Grid
		buffer.write(user.nick.padEnd(16, "\0"), 24, 16, "utf8");
		buffer.writeUInt32BE(0, 40); // Icon
		buffer.writeUInt32BE(0, 44); // Schema
		buffer.writeUInt32BE(0, 48); // Pic
		buffer.writeUInt32BE(messageBuffer.length, 52);
		messageBuffer.copy(buffer, 56);
		user.socket.write(this.makeHead(10003, user.userID, 0, buffer.length));
		user.socket.write(buffer);
		this.log("RESPONSE", `發送文本通知 (UserID: ${user.userID}, Msg: ${message})`);
	}
	handlePetGoHome(socket, userID, data) {
		this.log("ACTION", "寵物回家");
		const cmdID = data.readUInt32BE(5);
		const uid = data.readUInt32BE(11);
		const spriteID = data.readUInt32BE(15);
		this.log("INFO", ` CmdID: ${cmdID}, userID: ${userID} uid: ${uid}, SpriteID: ${spriteID}`);
		const petData = [
			{ kind: 101, num: 1 },
			{ kind: 202, num: 2 }
		];
		const count = petData.length; // 寵物數量
		const packetLength = 4 + 1 + 4 + 4 + 4 + 8 * count; // 計算回應封包長度
		const response = Buffer.alloc(packetLength);
		let offset = 0;
		response.writeUInt32BE(packetLength, offset); offset += 4; // 總封包長度
		response.writeUInt8(1, offset); offset += 1; // 版本號
		response.writeUInt32BE(cmdID, offset); offset += 4; // CmdID
		response.writeUInt32BE(userID, offset); offset += 4; // 帳號
		response.writeUInt32BE(count, offset); offset += 4; // 寵物數量
		petData.forEach(pet => {
			response.writeUInt32BE(pet.kind, offset); offset += 4;
			response.writeUInt32BE(pet.num, offset); offset += 4;
		});
		socket.write(response);
		this.log("RESPONSE", `發送寵物返回封包 (count: ${count}, total length: ${packetLength})`);
	}
	handleBlacklist(socket, userID) {
		this.log("ACTION", `黑名單 (UserID: ${userID})`);
		const body = Buffer.alloc(4);
		body.writeUInt32BE(0, 0);
		const head = this.makeHead(609, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送黑名單封包 (長度: ${head.length + body.length})`);
	}
	handleIsFinishedSth(socket, userID, data) {
		this.log("ACTION", `完成狀態查詢 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 4) {
			this.log("ERROR", `封包長度不足，無法讀取 type`);
			return;
		}
		const type = data.readUInt32BE(offset + 1);
		const body = this.makeIsFinishedSth(type);
		const head = this.makeHead(10101, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送完成狀態封包 (UserID: ${userID}, Type: ${type})`);
	}
	handleQueryRewardStatus(socket, userID, data) {
		this.log("ACTION", `查詢領取狀態 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 4) {
			this.log("ERROR", `封包長度不足，無法讀取 type`);
			return;
		}
		const type = data.readUInt32BE(offset + 1);
		const body = this.makeIsFinishedSth(type);
		const head = this.makeHead(8606, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送查詢領取狀態封包 (UserID: ${userID}, Type: ${type})`);
	}
	handleWalk(socket, userID, data) {
		this.log("ACTION", `走路 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 12) {
			this.log("ERROR", `封包長度不足，無法讀取坐標`);
			return;
		}
		const endX = data.readUInt32BE(offset + 1);
		const endY = data.readUInt32BE(offset + 5);
		const moveID = data.readUInt32BE(offset + 9);
		if (endX < 0 || endY < 0 || endX > 5000 || endY > 5000) {
			this.log("ERROR", `無效坐標 (X:${endX}, Y:${endY})`);
			return;
		}
		this.updateUserPosition(userID, endX, endY);
		this.broadcastWalk(userID, endX, endY, moveID);
	}
	updateUserPosition(userID, endX, endY) {
		if (!this.users.has(userID)) {
			this.users.set(userID, { userID, x: endX, y: endY });
		} else {
			const user = this.users.get(userID);
			user.x = endX;
			user.y = endY;
		}
	}
	getUserMapID(userID) {
		for (const [mapID, users] of this.maps.entries()) {
			if (users.find(user => user.userID === userID)) {
				return mapID;
			}
		}
		return null;
	}
	broadcastWalk(userID, endX, endY, moveID) {
		this.log("ACTION", `廣播走路: UserID ${userID}, X ${endX}, Y ${endY}, MoveID ${moveID}`);
		const user = this.users.get(userID);
		if (!user) {
			this.log("ERROR", `找不到使用者 ${userID}，無法廣播走路`);
			return;
		}
		const mapID = this.getUserMapID(userID);
		const mapUsers = this.maps.get(mapID) || [];
		const body = (userID, endX, endY, id) => {
			const buffer = Buffer.alloc(12);
			buffer.writeUInt32BE(endX, 0);
			buffer.writeUInt32BE(endY, 4);
			buffer.writeUInt32BE(id, 8);
			return buffer;
		}
		for (const mapUser of mapUsers) {
			const head = this.makeHead(303, mapUser.userID, 0, body.length);
			mapUser.socket.write(head);
			mapUser.socket.write(body);
		}
	}
	handleGetServerTime(socket, userID) {
		this.log("ACTION", `取得伺服器時間 (UserID: ${userID})`);
		const body = Buffer.alloc(8);
		const unixTime = Math.floor(Date.now() / 1000);
		body.writeUInt32BE(unixTime, 0);
		body.writeUInt32BE(0, 4);
		const head = this.makeHead(10301, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送伺服器時間封包 (UserID: ${userID}, Time: ${unixTime})`);
	}
	handleQueryNpcTasks(socket, userID, data) {
		this.log("ACTION", `查詢 NPC 任務狀態 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 4) {
			this.log("ERROR", `封包長度不足，無法讀取 NPC ID`);
			return;
		}
		const npcID = data.readUInt32BE(offset + 1);
		// const body = makeAllNpcJob(npcID)=> {
		// 	const buffer = Buffer.alloc(4);
		// 	buffer.writeUInt32BE(0, 0); // jobCount (0: 無任務)
		// 	return buffer;
		// }
		const body = Buffer.from(
			"\x00\x00\x00\x07\x00\x00\x00\x09\x00\x00\x00\x04\xFF\xFF\xFF\x38\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x07\xFF\xFF\xFF\x38\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x07\xFF\xFF\xFF\x38\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x19\x00\x00\x00\x08\xFF\xFF\xFF\x38\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x1A\x00\x00\x00\x08\xFF\xFF\xFF\x38\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\x09\xFF\xFF\xFF\x38\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00",
			"binary"
		);
		const head = this.makeHead(3106, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送 NPC 任務查詢封包 (UserID: ${userID}, NPC ID: ${npcID})`);
	}
	makeMapUserInfo(user) {
		const buffer = Buffer.alloc(223);
		buffer.writeUInt32BE(user.userID, 0);
		buffer.write(user.nick.padEnd(16, "\x00"), 4, "binary");
		buffer.writeUInt32BE(0, 22); // ParentID
		buffer.writeUInt32BE(0, 25); // ChildCount
		buffer.writeUInt32BE(0, 29); // NewChildCount
		buffer.writeUInt32BE(user.color, 33);
		buffer.writeUInt32BE(user.vip ? 1 : 0, 37);
		buffer.writeUInt32BE(user.map, 41);
		buffer.writeUInt32BE(0, 45); // MapType
		buffer.writeUInt8(user.status, 49);
		buffer.writeUInt32BE(user.action, 50);
		buffer.writeUInt32BE(user.petAction, 54);
		buffer.writeUInt8(user.direction, 58);
		buffer.writeUInt32BE(user.x, 59);
		buffer.writeUInt32BE(user.y, 63);
		buffer.writeUInt32BE(user.grid, 67);
		buffer.writeUInt32BE(user.action2, 71);
		buffer.writeUInt32BE(0, 75); // PetID
		buffer.write("".padEnd(16, "\x00"), 79, "binary"); // PetName
		buffer.writeUInt32BE(0, 95); // PetColor
		buffer.writeUInt8(0, 99); // PetLevel
		buffer.writeUInt32BE(0, 100); // Reserved1
		buffer.writeUInt32BE(0, 104); // PetSick
		buffer.writeUInt32BE(0, 108); // Skill_Fire
		buffer.writeUInt32BE(0, 112); // Skill_Water
		buffer.writeUInt32BE(0, 116); // Skill_Wood
		buffer.writeUInt32BE(0, 120); // Skill_Type
		buffer.writeUInt32BE(0, 124); // Skill_Value
		buffer.writeUInt8(0, 128); // Item1
		buffer.writeUInt8(0, 129); // Item2
		buffer.writeUInt8(0, 130); // Item3
		buffer.writeUInt32BE(0, 131); // Pet_Cloth
		buffer.writeUInt32BE(0, 135); // Pet_Honor
		buffer.writeUInt32BE(0, 139); // Can_Fly
		buffer.write("".padEnd(32, "\x00"), 143, "binary"); // Activity
		buffer.writeUInt32BE(0, 175); // Dragon ID
		buffer.write("".padEnd(16, "\x00"), 179, "binary"); // Dragon Nickname
		buffer.writeUInt32BE(0, 195); // Growth
		buffer.writeUInt32BE(0, 199); // DigTreasureLvl
		buffer.writeUInt32BE(0, 203); // HasCar
		buffer.writeUInt32BE(0, 207); // HasAnimal
		buffer.writeUInt32BE(0, 211); // RoleType
		buffer.writeUInt8(0, 215); // ItemCount
		buffer.writeUInt32BE(user.superGuide, 219);
		return buffer;
	}
	handleAllSceneUser(socket, userID, data) {
		this.log("ACTION", `取得地圖使用者 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 4) {
			this.log("ERROR", `封包長度不足，無法讀取 MapID`);
			return;
		}
		const mapID = data.readUInt32BE(offset + 1);
		const body = (map) => {
			const users = this.maps.get(map) || [];
			const bufferArray = [];
			const headerBuffer = Buffer.alloc(4);
			headerBuffer.writeUInt32BE(users.length, 0);
			bufferArray.push(headerBuffer);
			users.forEach((user) => {
				bufferArray.push(this.makeMapUserInfo(user));
			});
			return Buffer.concat(bufferArray);
		}
		const head = this.makeHead(405, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送地圖使用者列表封包 (UserID: ${userID}, MapID: ${mapID})`);
	}
	handleGetMapInfo(socket, userID, data) {
		this.log("ACTION", `取得地圖資訊 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 8) {
			this.log("ERROR", `封包長度不足，無法讀取 MapID`);
			return;
		}
		const mapID = data.readUInt32BE(offset + 1);
		const type = data.readUInt32BE(offset + 5);
		const body = (mapID, type) => {
			const buffer = Buffer.alloc(80);
			buffer.writeUInt32BE(mapID, 0); // MapID
			buffer.writeUInt32BE(type, 4); // MapType
			const mapName = this.mapsInfo[mapID] || ""; // 映射地圖名稱
			buffer.write(mapName.padEnd(64, "\x00"), 8, "binary"); // 地圖名稱
			buffer.writeUInt32BE(1, 72); // Type
			buffer.writeUInt32BE(0, 76); // ItemCount
			return buffer;
		};
		const head = this.makeHead(406, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送地圖資訊封包 (UserID: ${userID}, MapID: ${mapID}, Type: ${type})`);
	}
	handleGetLoginSession(socket, userID) {
		this.log("ACTION", `取得登入 Session (UserID: ${userID})`);
		const body = Buffer.alloc(16, 0);
		const head = this.makeHead(426, userID, 0, body.length);
		socket.write(head);
		socket.write(body);

		this.log("RESPONSE", `發送登入 Session 封包 (UserID: ${userID}, Session: 全 0)`);
	}
	handleMagicSpiritBagInfo(socket, userID) {
		this.log("ACTION", `取得玩家職業數據 (UserID: ${userID})`);
		const body = Buffer.from(
			"\x00\x00\x00\x06\x53\xC3\x69\xD3\x00\x26\x3E\xFC\x03\x04\x00\x00\x01\x90\x00\x93\x00\x5A\x00\x23\x0B\xC0\x01\x00\x00\x00\x01\x00\x54\x54\xF9\xA9\x00\x26\x3E\xC4\x02\x05\x00\x00\x03\x39\x00\x90\x00\x47\x00\x0D\x03\xEC\x01\x07\xD2\x00\x00\x00\x54\x54\xF9\xE0\x00\x26\x3E\xE0\x03\x08\x00\x00\x06\x27\x00\xA7\x00\x4E\x00\x1F\x00\x00\x00\x00\x00\x00\x00\x00\x59\xD1\x03\xC6\x00\x26\x3F\x4F\x01\x01\x00\x00\x00\x00\x00\xC8\x01\x5E\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x59\xD4\x53\x51\x00\x26\x3F\x50\x02\x01\x00\x00\x00\x00\x00\xC8\x01\x5E\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x59\xD4\x53\x52\x00\x26\x3F\x51\x03\x01\x00\x00\x00\x00\x00\xC8\x01\x5E\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00\x25\x36\x00\xAE\x5B\x47\x53\x04\xE9\x0B\x07\xD5\x80\x4F\x71\x75\x41\x4E\x0C\x00\x13\x14\x0E\xD9\x1E\xE1\x68\x12\x1C\xFD\x3A\x7E\x25\x2A\x77\xB8\x54\xD0\x41\x0C\x17\x18\xD2\x5C\x1A\x77\x32\x69\x08\x76\x55\xC0\xD3\x25\x30\x48\xEC\x56\x46\x41\x08\x0F\x39\x13\x82\x5D\x5D\x77\x3F\x6B\xE4\x23\x06\xEB\x7A\x25\x2A\x22\x7C\xAD\xA3\x41\x12\x32\xE0\x10\x1A\x5D\x1A\x71\x15\x68\xAF\x22\x4F\x39\x65\x25\x2A\x76\x28\x54\x43\x41\x08\x55\xD1\x10\xD4\x5D\x00\x48\x7D\x69\x09\x22\x01\x39\x7A\x25\xE2\x77\x76\x54\x19\x41\x08\x0C\x00\x13\x12\x5D\x1A\x2E\xE4\x3B\x59\x22\x1B\x06\x2A\x27\x2B\x76\x28\x54\x43\x41\xC0\x0D\x5E\x13\x42\x5D\x1A\x77\x32\x68\x08\x22\x01\x60\xAC\x76\x78\x76\x32\x6B\x12\x42\x09\x0C\x00\x13\x12\x5D\xD2\x76\x6C\x68\x58\x22\x01\x39\x7A\x25\x2A\x76\x28\x71\x75\x41\xC6\x52\x47\x40\x46\xDC\x17\x70\xE7\xE8\x47\x53\x74\x78\x34",
			"binary"
		);
		const head = this.makeHead(12018, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送玩家職業封包 (UserID: ${userID})`);
	}
	handleGetLimitInfo(socket, userID, data) {
		this.log("ACTION", `取得通用狀態標記 (UserID: ${userID})`);
		const offset = 17;
		const listSize = data.readUInt32BE(offset + 1);
		const body = Buffer.alloc(4 + listSize * 4);
		body.writeUInt32BE(listSize, 0);
		for (let i = 0; i < listSize; i++) {
			body.writeUInt32BE(5, 4 + i * 4);
		}
		const head = this.makeHead(11009, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送通用狀態標記封包 (UserID: ${userID}, ListSize: ${listSize})`);
	}
	handleGetMiniGameStep(socket, userID) {
		this.log("ACTION", `查看小遊戲步驟 (UserID: ${userID})`);
		const body = Buffer.alloc(12, 0);
		const head = this.makeHead(8817, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送小遊戲步驟封包 (UserID: ${userID}, Data: 12 Bytes 全 0)`);
	}
	handleMagicSpiritUserInfo(socket, userID) {
		this.log("ACTION", ` MAGICSPIRIT_USER_INFO (UserID: ${userID})`);
		const body = Buffer.from(
			"\x04\x2E\xD56\x04\x00\x00\x00\x72\x00\x00\x01\x00\x00\x5D\x54\x54\xF9\x9B\x00\x28\x00\x27\x01\x53\xC3\x69\xD3\x54\x54\xF9\xE0\x00\x00\x00\x00\x00\x00\x00\x00\x54\x54\xF9\xA9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			"binary"
		);
		const head = this.makeHead(12004, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送 MAGICSPIRIT_USER_INFO 封包 (UserID: ${userID}, Data: 124 Bytes)`);
	}
	handleGetMyProfession(socket, userID) {
		this.log("ACTION", `取得我的職業 (UserID: ${userID})`);
		const body = Buffer.from(
			"\x05\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			"binary"
		);
		const head = this.makeHead(1328, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送我的職業資訊封包 (UserID: ${userID}, Data: 226 Bytes)`);
	}
	handleGetUserInfo(socket, userID, data) {
		this.log("ACTION", ` getUserInfo (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 4) {
			this.log("ERROR", "封包長度不足，無法讀取使用者 ID");
			return;
		}
		const targetUserID = data.readUInt32BE(offset + 1);
		const body = (id) => {
			const buffer = Buffer.alloc(27);
			buffer.writeUInt32BE(id, 0); // User ID
			buffer.writeUInt8(1, 4); // Level
			buffer.writeUInt32BE(0, 5); // Exp
			buffer.writeUInt32BE(95, 9); // Need Exp
			buffer.writeUInt16BE(30, 13); // Bag Size
			buffer.writeUInt16BE(3, 15); // Exchange Bag Size
			buffer.writeUInt8(1, 17); // Max Training Num
			buffer.writeUInt8(0, 18); // Training Level
			buffer.writeUInt32BE(0, 19); // Instrument 1
			buffer.writeUInt32BE(0, 23); // Instrument 2
			return buffer;
		};
		const head = this.makeHead(11085, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送使用者資訊封包 (查詢目標 UserID: ${targetUserID})`);
	}
	handleGetKnightTransferState8974(socket, userID) {
		this.log("ACTION", `getKnightTransferState (UserID: ${userID})`);
		const body = Buffer.alloc(4, 0);
		const head = this.makeHead(9124, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送 Knight Transfer State 封包 (UserID: ${userID}, Data: 4 Bytes 全 0)`);
	}
	handleUnreadPostcardCount(socket, userID) {
		this.log("ACTION", `未讀明信片數目 (UserID: ${userID})`);
		const body = Buffer.alloc(4);
		body.writeUInt32BE(0, 0); // TEMP (未讀明信片數目，預設為 0)
		const head = this.makeHead(805, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送未讀明信片數目封包 (UserID: ${userID}, Data: ${body.length} Bytes)`);
	}
	handleElementKnightInfo(socket, userID) {
		this.log("ACTION", `元素騎士資訊 (UserID: ${userID})`);
		const body = Buffer.alloc(85);
		body.writeUInt32BE(0, 0);  // ID
		body.writeUInt32BE(2, 4);  // Type
		body.write("RecMole", 8, "utf8"); // Nickname (最多 16 個字)
		body.writeUInt32BE(0, 24); // Exp
		body.writeUInt32BE(0, 28); // Current Strength
		body.writeUInt32BE(0, 32); // Max Strength
		body.writeUInt32BE(2, 36); // Talent
		body.writeUInt32BE(0, 40); // Cooldown
		body.writeUInt32BE(0, 44); // Min Attack
		body.writeUInt32BE(0, 48); // Max Attack
		body.writeUInt32BE(0, 52); // Min Defense
		body.writeUInt32BE(0, 56); // Max Defense
		body.writeUInt32BE(0, 60); // PvP Wins
		body.writeUInt32BE(0, 64); // PvP Losses
		body.writeUInt32BE(0, 68); // Chasm
		body.writeUInt32BE(0, 72); // Rank
		body.writeUInt32BE(0, 76); // Count
		body.writeUInt32BE(0, 80); // Count 2 (如果 ElementKnightCardInfo 不為 0)
		const head = this.makeHead(8990, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送元素騎士資訊封包 (UserID: ${userID}, Data: ${body.length} Bytes)`);
	}
	handleCommitteePresidentVote(socket, userID) {
		this.log("ACTION", `屋委會會長投票 (UserID: ${userID})`);
		const body = Buffer.from(
			"\x00\x16\x00\x01\x50\x70\xFF\xFF\xF8\x00\x00\x00\x00\x03\x81\x08\x00\x00\x00\x00\x00\x00\x58\x09\x25\xDD\xC8\x40\x00\x00\x00\x00",
			"binary"
		);
		const head = this.makeHead(2008, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送屋委會會長投票封包 (UserID: ${userID}, Data: 32 Bytes)`);
	}
	handleGetKnightTransferState(socket, userID) {
		this.log("ACTION", `GET_KNIGHT_TRANSFER_STATE (UserID: ${userID})`);

		const body = Buffer.alloc(4, 0);
		body.writeUInt32BE(2, 0); // 設定返回值 2

		const head = this.makeHead(8974, userID, 0, body.length);

		socket.write(head);
		socket.write(body);

		this.log("RESPONSE", `發送 KNIGHT_TRANSFER_STATE 封包 (UserID: ${userID}, Data: 4 Bytes, Value: 2)`);
	}
	handleComeBackStatus(socket, userID, data) {
		this.log("ACTION", `COME_BK_STATUS (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 5) {
			this.log("ERROR", `封包長度不足，無法讀取數據類型`);
			return;
		}
		const type = data.readUInt32BE(offset + 1);
		if (type === 2025) { // 暫時忽略
			this.log("INFO", `忽略 COME_BK_STATUS (Type: 2025)`);
			return;
		}
		const body = Buffer.alloc(12);
		body.writeUInt32BE(type, 0);  // Type
		body.writeUInt32BE(0, 4);     // Value1
		body.writeUInt32BE(0, 8);     // Value2
		const head = this.makeHead(8755, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送 COME_BK_STATUS 封包 (UserID: ${userID}, Type: ${type}, Data: ${body.length} Bytes)`);
	}
	handleTimeGreeting(socket, userID, data) {
		this.log("ACTION", `時間問候 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 4) {
			this.log("ERROR", `封包長度不足，無法讀取數據類型`);
			return;
		}
		const type = data.readUInt32BE(offset + 1);
		const body = Buffer.alloc(12);
		body.writeUInt32BE(type, 0); // Type
		body.writeUInt32BE(8, 4); // Unknown
		body.writeUInt32BE(2356, 8); // Sec
		const head = this.makeHead(10011, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送時間問候封包 (UserID: ${userID}, Type: ${type}, Data: ${body.length} Bytes)`);
	}
	handleUserAction(socket, userID, data) {
		this.log("ACTION", `使用者動作 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 6) {
			this.log("ERROR", `封包長度不足，無法讀取動作數據`);
			return;
		}
		const action = data.readUInt32BE(offset + 1);
		const direction = data.readUInt8(offset + 5);
		this.performUserAction(userID, action, direction);
	}
	/*** 執行動作 ***/
	performUserAction(userID, action, direction) {
		if (!this.users.has(userID)) {
			this.log("ERROR", `使用者 ${userID} 不存在，無法執行動作`);
			return;
		}
		const user = this.users.get(userID);
		user.action = action;
		user.direction = direction;
		this.broadcastAction(user, action, direction);
	}
	/*** 廣播動作 ***/
	broadcastAction(user, action, direction) {
		const mapUsers = this.getUsersByMap(user.map);
		const body = () => {
			const buffer = Buffer.alloc(9);
			buffer.writeUInt32BE(user.userID, 0); // UserID
			buffer.writeUInt32BE(action, 4); // Action
			buffer.writeUInt8(direction, 8); // Direction
			return buffer;
		};
		const head = this.makeHead(305, user.userID, 0, body.length);
		for (const targetUser of mapUsers) {
			targetUser.socket.write(head);
			targetUser.socket.write(body);
		}
		this.log("RESPONSE", `廣播動作 (UserID: ${user.userID}, Action: ${action}, Direction: ${direction})`);
	}
	handleViewInventory(socket, userID, data) {
		this.log("ACTION", `查看背包 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 11) {
			this.log("ERROR", `封包長度不足，無法讀取背包數據`);
			return;
		}
		const targetUserID = data.readUInt32BE(offset + 1);
		const type = data.readUInt32BE(offset + 5);
		const flag = data.readUInt8(offset + 9);
		const newType = data.readUInt8(offset + 10);
		this.log("INFO", `查看背包 - 目標使用者: ${targetUserID}, 類型: ${type}, 標誌: ${flag}, 新類型: ${newType}`);
		const body = Buffer.alloc(1, 0);
		const head = this.makeHead(507, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送查看背包回應 (UserID: ${userID}, Data: 1 Byte 全 0)`);
	}
	handleChatMessage(socket, userID, data) {
		this.log("ACTION", `聊天 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 9) {
			this.log("ERROR", `封包長度不足，無法讀取聊天數據`);
			return;
		}
		const toWho = data.readUInt32BE(offset + 1);
		const msgLen = data.readUInt32BE(offset + 5);
		if (data.length < offset + 9 + msgLen - 2) {
			this.log("ERROR", `封包長度不足，無法讀取完整聊天內容`);
			return;
		}
		const message = data.toString("utf8", offset + 9, offset + 9 + msgLen - 2);
		const maxMessageLength = 200;
		if (message.length > maxMessageLength) {
			this.log("ERROR", `聊天訊息過長: ${message.length} > ${maxMessageLength}`);
			return;
		}
		this.processChatMessage(userID, toWho, message);
	}
	/*** 處理聊天訊息 ***/
	processChatMessage(userID, toWho, message) {
		if (!this.users.has(userID)) {
			this.log("ERROR", `使用者 ${userID} 不存在，無法發送聊天訊息`);
			return;
		}
		const user = this.users.get(userID);
		if (toWho === 0) {
			// 處理全聊天
			if (message === "/color") {
				this.broadcastChat(user, toWho, "隨機變色");
				user.color = Math.floor(Math.random() * 0xffffffff);
				this.sendAllSceneUsers(user.map);
				return;
			}
			this.broadcastChat(user, toWho, message);
		} else if (this.users.has(toWho)) {
			// 處理私聊
			this.sendChat(this.users.get(toWho), user, message);
		}
		this.log("CHAT", `[${user.userID}] ${user.nick}: ${message}`);
	}
	/*** 發送聊天訊息 ***/
	sendChat(targetUser, userSender, message) {
		const body = () => {
			const buffer = Buffer.alloc(28 + message.length);
			buffer.writeUInt32BE(user.userID, 0); // 發送者帳號
			buffer.write(userSender.nick.padEnd(16, "\0"), 4, 16, "utf8"); // 暱稱
			buffer.writeUInt32BE(0, 20); // 好友狀態
			buffer.writeUInt32BE(message.length, 24); // 訊息長度
			buffer.write(message, 28, message.length, "utf8"); // 訊息內容
			return buffer;
		};
		const head = this.makeHead(302, targetUser.userID, 0, body.length);
		targetUser.socket.write(head);
		targetUser.socket.write(body);
		this.log("RESPONSE", `發送私聊訊息 (From: ${userSender.userID}, To: ${targetUser.userID}, Msg: ${message})`);
	}
	/*** 廣播聊天訊息 ***/
	broadcastChat(userSender, toWho, message) {
		const mapUsers = this.getUsersByMap(user.map);
		const body = this.makeChatPacket(userSender, toWho, message);
		const head = this.makeHead(302, userSender.userID, 0, body.length);
		for (const user of mapUsers) {
			user.socket.write(head);
			user.socket.write(body);
		}
		this.log("RESPONSE", `廣播聊天訊息 (From: ${userSender.userID}, To: ${toWho}, Msg: ${message})`);
	}
	handleEnterMap(socket, userID, data) {
		this.log("ACTION", `進入地圖 (UserID: ${userID})`);
		const offset = 17;
		if (data.length < offset + 25) {
			this.log("ERROR", `封包長度不足，無法讀取地圖數據`);
			return;
		}
		const newMapID = data.readUInt32BE(offset + 1);
		const newMapType = data.readUInt32BE(offset + 5);
		const oldMapID = data.readUInt32BE(offset + 9);
		const oldMapType = data.readUInt32BE(offset + 13);
		const newGrid = data.readUInt32BE(offset + 17);
		const oldGrid = data.readUInt32BE(offset + 21);
		if (!this.users.has(userID)) {
			this.log("ERROR", `使用者 ${userID} 不存在，無法進入地圖`);
			return;
		}
		const user = this.users.get(userID);
		this.changeUserMap(user, newMapID);
	}
	/*** 進入地圖 ***/
	enterMap(user, newMapID, newMapType) {
		this.log("ACTION", `使用者 ${user.userID} 進入地圖 (MapID: ${newMapID})`);
		const oldMapID = user.map;
		this.changeUserMap(user, newMapID);
		const mapUsers = this.getUsersByMap(newMapID);
		this.broadcastEnterMap(mapUsers, user);
	}
	/*** 離開地圖 ***/
	handleLeaveMap(socket, userID) {
		this.log("ACTION", `離開地圖 (UserID: ${userID})`);
		if (!this.users.has(userID)) {
			this.log("ERROR", `使用者 ${userID} 不存在，無法離開地圖`);
			return;
		}
		const user = this.users.get(userID);
		const mapUsers = this.getUsersByMap(user.map);
		this.removeUserFromMap(user);
		this.broadcastLeaveMap(mapUsers, user);
	}
	/*** 更改使用者地圖 ***/
	changeUserMap(user, newMapID) {
		const oldMapID = user.map;
		this.removeUserFromMap(user);
		user.map = newMapID;
		this.addUserToMap(user, newMapID);
	}
	/*** 將使用者從地圖移除 ***/
	removeUserFromMap(user) {
		const oldMapID = user.map;
		if (!oldMapID) return; // 確保使用者確實有地圖紀錄
		const mapUsers = this.getUsersByMap(oldMapID);
		const updatedUsers = mapUsers.filter(u => u.userID !== user.userID);
		// 確保 `maps` 更新後，也同步 `users`
		this.maps.set(oldMapID, updatedUsers);
		this.users.set(user.userID, { ...user, map: null });
		this.broadcastLeaveMap(updatedUsers, user);
	}
	/*** 廣播進入地圖 ***/
	broadcastEnterMap(mapUsers, userEntering) {
		const body = (user) => {
			const buffer = Buffer.alloc(8);
			buffer.writeUInt32BE(user.userID, 0);
			buffer.writeUInt32BE(user.map, 4);
			return buffer;
		};
		const head = this.makeHead(401, userEntering.userID, 0, body.length);
		for (const user of mapUsers) {
			user.socket.write(head);
			user.socket.write(body);
		}
		this.log("RESPONSE", `廣播進入地圖 (UserID: ${userEntering.userID}, MapID: ${userEntering.map})`);
	}
	/*** 廣播離開地圖 ***/
	broadcastLeaveMap(mapUsers, userLeaving) {
		const body = (user) => {
			const buffer = Buffer.alloc(4);
			buffer.writeUInt32BE(user.userID, 0);
			return buffer;
		};
		const head = this.makeHead(402, userLeaving.userID, 0, body.length);
		for (const user of mapUsers) {
			user.socket.write(head);
			user.socket.write(body);
		}
		this.log("RESPONSE", `廣播離開地圖 (UserID: ${userLeaving.userID})`);
	}
	/*** 將使用者新增到地圖 ***/
	addUserToMap(user, newMapID) {
		this.users.set(user.userID, { ...user, map: newMapID });
		const mapUsers = this.getUsersByMap(user.map);
		mapUsers.push(user);
		this.broadcastEnterMap(mapUsers, user);
	}
	/*** 取得地圖內的使用者 ***/
	getUsersByMap(mapID) {
		return Array.from(this.users.values()).filter(user => user.map === mapID);
	}
	handlePetCountInMap(socket, userID) {
		this.log("ACTION", `拉寵物在地圖中的數量 (UserID: ${userID})`);
		const body = Buffer.alloc(4, 0);
		const head = this.makeHead(233, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送寵物數量封包 (UserID: ${userID}, Data: 4 Bytes 全 0)`);
	}
	handlePlatformMessageStats(socket, userID) {
		this.log("ACTION", `統計平台消息 (UserID: ${userID})`);
		const body = Buffer.alloc(1, 0);
		const head = this.makeHead(6034, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送統計平台消息封包 (UserID: ${userID}, Data: 1 Byte 全 0)`);
	}
	handlePetTaskList(socket, userID) {
		this.log("ACTION", `拉取寵物任務列表 (UserID: ${userID})`);
		const body = Buffer.alloc(8, 0);
		const head = this.makeHead(228, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送寵物任務列表封包 (UserID: ${userID}, Data: 8 Bytes 全 0)`);
	}
	handleSuperLamuCheck(socket, userID) {
		this.log("ACTION", `查詢是否已有超級拉姆 (UserID: ${userID})`);
		const body = Buffer.alloc(1, 0);
		const head = this.makeHead(232, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送超級拉姆查詢封包 (UserID: ${userID}, Data: 1 Byte 全 0)`);
	}
	handleLoginStreak30Days(socket, userID) {
		this.log("ACTION", `查看連續30天登入資訊 (UserID: ${userID})`);
		const body = Buffer.alloc(24, 0);
		const head = this.makeHead(6024, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送連續30天登入資訊封包 (UserID: ${userID}, Data: 24 Bytes 全 0)`);
	}
	handleLoginStreakSummary(socket, userID) {
		this.log("ACTION", `查看連續30天登入摘要資訊 (UserID: ${userID})`);
		const body = Buffer.alloc(8, 0);
		const head = this.makeHead(6026, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送連續30天登入摘要資訊封包 (UserID: ${userID}, Data: 8 Bytes 全 0)`);
	}
	handleMagicCourseQuery(socket, userID) {
		this.log("ACTION", `查詢魔法課程 (UserID: ${userID})`);
		const body = Buffer.alloc(4, 0);
		const head = this.makeHead(1496, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送魔法課程查詢封包 (UserID: ${userID}, Data: 4 Bytes 全 0)`);
	}
	handlePaymentPasswordRequirement(socket, userID) {
		this.log("ACTION", `取得是否需要支付密碼 (UserID: ${userID})`);
		const body = Buffer.alloc(4, 0);
		const head = this.makeHead(8920, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送支付密碼查詢封包 (UserID: ${userID}, Data: 4 Bytes 全 0)`);
	}
	handleSMCTaskList(socket, userID) {
		this.log("ACTION", `SMC 任務列表 (UserID: ${userID})`);
		const body = Buffer.alloc(4, 0);
		const head = this.makeHead(216, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送 SMC 任務列表封包 (UserID: ${userID}, Data: 4 Bytes 全 0)`);
	}
	handleRegistrationRedirectSession(socket, userID) {
		this.log("ACTION", `註冊會員跳轉頁面 Session (UserID: ${userID})`);
		const sessionString = "[C\x8BE435370a2b2f3c57c07f3564f792f1650";
		const body = Buffer.from(sessionString, "utf8");
		const head = this.makeHead(10302, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送註冊會員跳轉頁面 Session 封包 (UserID: ${userID}, Data: ${body.length} Bytes)`);
	}
	handleInitPlayerEx(socket, userID) {
		this.log("ACTION", `CLI_PROTO_INIT_PLAYER_EX (UserID: ${userID})`);
		const body = Buffer.alloc(1, 0);
		const head = this.makeHead(11010, userID, 0, body.length);
		socket.write(head);
		socket.write(body);
		this.log("RESPONSE", `發送 CLI_PROTO_INIT_PLAYER_EX 封包 (UserID: ${userID}, Data: 1 Byte 全 0)`);
	}
	handleAuthCode(socket) {
		this.log("ACTION", '發送驗證碼');
		const packetLength = 25;
		const response = Buffer.alloc(packetLength);
		response.writeUInt32BE(packetLength, 0);
		response.writeUInt8(1, 4);
		response.writeUInt32BE(101, 5);
		response.writeUInt32BE(0, 9);
		const codeID = crypto.randomBytes(16)
		codeID.copy(response, 13);
		this.log("RESPONSE", "發送驗證碼封包");
		socket.write(response);
	}
	/*** 通用標頭 ***/
	makeHead(cmdID, userID, errorID, bodyLen) {
		const offset = 17; // 封包頭長度
		const buffer = Buffer.alloc(offset + bodyLen);
		buffer.writeUInt32BE(offset + bodyLen, 0);  // PkgLen
		buffer.writeUInt8(5, 4); // Version
		buffer.writeUInt32BE(cmdID, 5); // Command
		buffer.writeUInt32BE(userID, 9); // UserID
		buffer.writeUInt32BE(errorID, 13); // Result
		return buffer;
	}
	/*** 通用完成狀態 ***/
	makeIsFinishedSth(type) {
		const buffer = Buffer.alloc(8);
		buffer.writeUInt32BE(type, 0);  // 類型
		buffer.writeUInt32BE(1022, 4); // 狀態碼 (固定1022)
		return buffer;
	}
}
new TCPServerManager();
