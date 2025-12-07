/*
 * Copyright 2015 - 2024 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.protocol;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import org.traccar.BaseProtocolDecoder;
import org.traccar.session.DeviceSession;
import org.traccar.NetworkMessage;
import org.traccar.Protocol;
import org.traccar.helper.BitUtil;
import org.traccar.helper.Checksum;
import org.traccar.helper.DateBuilder;
import org.traccar.helper.ObdDecoder;
import org.traccar.helper.UnitsConverter;
import org.traccar.model.CellTower;
import org.traccar.model.Network;
import org.traccar.model.Position;

import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class CastelProtocolDecoder extends BaseProtocolDecoder {

    private static final Map<Integer, Integer> PID_LENGTH_MAP = new HashMap<>();

    static {
        // --- 1. Standard OBD-II PIDs (Default Baseline) ---
        int[] l1 = {
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0d,
            0x0e, 0x0f, 0x11, 0x12, 0x13, 0x1c, 0x1d, 0x1e, 0x2c,
            0x2d, 0x2e, 0x2f, 0x30, 0x33, 0x43, 0x45, 0x46,
            0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x51, 0x52,
            0x5a
        };
        int[] l2 = {
            0x02, 0x03, 0x0a, 0x0c, 0x10, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x21, 0x22,
            0x23, 0x31, 0x32, 0x3c, 0x3d, 0x3e, 0x3f, 0x42,
            0x44, 0x4d, 0x4e, 0x50, 0x53, 0x54, 0x55, 0x56,
            0x57, 0x58, 0x59
        };
        int[] l4 = {
            0x00, 0x01, 0x20, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2a, 0x2b, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x40, 0x41, 0x4f
        };

        for (int i : l1) PID_LENGTH_MAP.put(i, 1);
        for (int i : l2) PID_LENGTH_MAP.put(i, 2);
        for (int i : l4) PID_LENGTH_MAP.put(i, 4);

        // --- 2. COMMERCIAL VEHICLE PIDs (Source: Rev 1.18 PDF) ---
        // Overrides standard OBD if conflict exists (e.g., 0x54)
        
        // 1-Byte Commercial PIDs
        int[] commL1 = {
            0x0054, 0x0253, 0x0255, 0x0256, 0x03d0, 0x022e, 0x022f, 0x059d, 
            0x0b9a, 0x005c, 0x0ba3, 0x0383, 0x0200, 0x0201, 0x05cb, 0x068b, 
            0x0980, 0x006e, 0x0045, 0x0046, 0x0661, 0x0254, 0x0257, 0x0258, 
            0x0259, 0x025a, 0x0056, 0x020f, 0x03c8, 0x03c7, 0x03c6, 0x04d5, 
            0x0051, 0x0208, 0x0209, 0x023B, 0x023C, 0x1081, 0x1082, 0x1083, 
            0x1084, 0x1091, 0x1092, 0x10a1, 0x10a2, 0x10d0, 0x1110, 0x1180, 
            0x1191, 0x1192, 0x1193, 0x1194, 0x11a0, 0x11b0, 0x11c0, 0x11d0, 
            0x11e0, 0x11f0, 0x1200, 0x1210, 0x1221, 0x1222, 0x1223, 0x1224, 
            0x1231, 0x1232, 0x1240, 0x1260, 0x1270, 0x1281, 0x1282, 0x1291, 
            0x1292, 0x1293, 0x12a0, 0x12b1, 0x12b2, 0x12b3, 0x12b4, 0x12c1, 
            0x12c2, 0x12c3, 0x12d1, 0x12d2, 0x12d3, 0x12f0, 0x1300, 0x1311, 
            0x1312, 0x1313, 0x1314, 0x1321, 0x1322, 0x1323, 0x1324, 0x1330, 
            0x1340, 0x1350, 0x1360, 0x1371, 0x1372, 0x1373, 0x1381, 0x1382, 
            0x1391, 0x1392, 0x1393, 0x1394, 0x13a1, 0x13a2, 0x13a3, 0x13a4, 
            0x13b0, 0x13c0, 0x13d1, 0x13d2, 0x13e0, 0x13f1, 0x13f2, 0x13f3, 
            0x13f4, 0x1401, 0x1402, 0x1403, 0x1411, 0x1412, 0x1421, 0x1422, 
            0x1423, 0x1431, 0x1432, 0x1440, 0x1450, 0x1460, 0x1471, 0x1472, 
            0x1473, 0x1474, 0x1475, 0x1480, 0x14a0, 0x1500, 0x1530, 0x1540, 
            0x1560, 0x1570, 0x1580, 0x15b0, 0x15c0, 0x1600, 0x1610, 0x1620, 
            0x1650, 0x1660, 0x1690, 0x16c0, 0x16d0, 0x16e0, 0x16f0, 0x17a0, 
            0x17c0, 0x17d0, 0x1810, 0x1fb1, 0x1fb2, 0x1fb3, 0x1fc1, 0x1fc2, 
            0x1fc3, 0x1fd1, 0x1fd2, 0x1fd3, 0x1fd4, 0x3001, 0x3002, 0x3006, 
            0x3007, 0x3009, 0x300a, 0x300b, 0x3047, 0x3049, 0x3109, 0x06e1
        };

        // 2-Byte Commercial PIDs
        int[] commL2 = {
            0x006a, 0x00be, 0x00ae, 0x00af, 0x00b0, 0x0034, 0x005e, 0x0064, 
            0x0065, 0x0066, 0x0069, 0x00ad, 0x00ba, 0x0203, 0x00a1, 0x059c, 
            0x0bfd, 0x0c47, 0x0c48, 0x0c49, 0x0c4e, 0x0c4f, 0x10f0, 0x1100, 
            0x1140, 0x16a0, 0x1710, 0x1780, 0x17e0, 0x1a00, 0x1a10, 0x1a60, 
            0x1ba0, 0x1bb0, 0x1bc0, 0x1bd0, 0x1be0, 0x1bf0, 0x1d20, 0x1d30, 
            0x1d40, 0x1980, 0x3036, 0x3037, 0x3038, 0x3039, 0x303a, 0x303b, 
            0x303c, 0x3048, 0x3260, 0x9ffe
        };

        // 4-Byte Commercial PIDs
        int[] commL4 = {
            0x0026, 0x005b, 0x0060, 0x00a8, 0x00b1, 0x00b6, 0x00b7, 0x00f5, 
            0x00f8, 0x00fa, 0x0084, 0x0392, 0x0396, 0x0664, 0x0665, 0x03ce, 
            0x001d, 0x0d1d, 0x046e, 0x0016, 0x006d, 0x006f, 0x006b, 0x0070, 
            0x0395, 0x00f4, 0x00f7, 0x00f9, 0x00b8, 0x00b9, 0x00ec, 0x03e9, 
            0x03ea, 0x03eb, 0x03ec, 0x03ed, 0x03ee, 0x0404, 0x0405, 0x10e0, 
            0x1120, 0x1130, 0x1150, 0x1160, 0x1170, 0x1250, 0x12e0, 0x1490, 
            0x14c0, 0x14f0, 0x1510, 0x1520, 0x15d0, 0x15e0, 0x15f0, 0x1630, 
            0x1640, 0x1670, 0x1680, 0x16b0, 0x1700, 0x1720, 0x1730, 0x1740, 
            0x1750, 0x1760, 0x1770, 0x17b0, 0x17f0, 0x1820, 0x1830, 0x1840, 
            0x1850, 0x1870, 0x1880, 0x1890, 0x18a0, 0x18d0, 0x18e0, 0x18f0, 
            0x1900, 0x1910, 0x1920, 0x1930, 0x1940, 0x1950, 0x1990, 0x19c0, 
            0x19d0, 0x19e0, 0x19f0, 0x1a40, 0x1a50, 0x1a70, 0x1a80, 0x1a90, 
            0x1aa0, 0x1ab0, 0x1ac0, 0x1ad0, 0x1ae0, 0x1af0, 0x1b00, 0x1b10, 
            0x1b20, 0x1b30, 0x1b40, 0x1b50, 0x1b60, 0x1b70, 0x1b80, 0x1b90, 
            0x1e40, 0x1e50, 0x1e60, 0x1e70, 0x1eb0, 0x1ec0, 0x1f40, 0x1f50, 
            0x1f60, 0x1f70, 0x1f80, 0x1f90, 0x1fa0, 0x3003, 0x3004, 0x3005, 
            0x3008, 0x300c, 0x300d, 0x3017, 0x3018, 0x3019, 0x301f, 0x3020, 
            0x3021, 0x3022, 0x3023, 0x3024, 0x3025, 0x3026, 0x302f, 0x3030, 
            0x3031, 0x3032, 0x3033, 0x3034, 0x3035, 0x303d, 0x303e, 0x3040, 
            0x3044, 0x3045, 0x304a, 0x3108
        };

        for (int i : commL1) PID_LENGTH_MAP.put(i, 1);
        for (int i : commL2) PID_LENGTH_MAP.put(i, 2);
        for (int i : commL4) PID_LENGTH_MAP.put(i, 4);

        // --- 3. PASSENGER CAR PIDs (Source: Rev 1.06 PDF) ---
        // 1-Byte Passenger PIDs
        int[] passL1 = {
            0x2104, 0x2105, 0x2106, 0x2107, 0x2108, 0x2109, 0x210b, 0x210d, 
            0x210e, 0x210f, 0x2111, 0x2112, 0x2113, 0x211c, 0x211d, 0x211e, 
            0x212c, 0x212d, 0x212e, 0x212f, 0x2130, 0x2133, 0x2143, 0x2145, 
            0x2146, 0x2147, 0x2148, 0x2149, 0x214a, 0x214b, 0x214c, 0x2151, 
            0x2152, 0x215a, 0x215b, 0x215c, 0x2161, 0x2162
        };
        // 2-Byte Passenger PIDs
        int[] passL2 = {
            0x2102, 0x2103, 0x210a, 0x210c, 0x2110, 0x2114, 0x2115, 0x2116,
            0x2117, 0x2118, 0x2119, 0x211a, 0x211b, 0x211f, 0x2121, 0x2122, 
            0x2123, 0x2131, 0x2132, 0x213c, 0x213d, 0x213e, 0x213f, 0x2142, 
            0x2144, 0x214d, 0x214e, 0x2150, 0x2153, 0x2154, 0x2155, 0x2156,
            0x2157, 0x2158, 0x2159, 0x215d, 0x215e, 0x2163, 0x219d
        };
        // 4-Byte Passenger PIDs
        int[] passL4 = {
            0x2100, 0x2101, 0x2120, 0x2124, 0x2125, 0x2126, 0x2127, 0x2128,
            0x2129, 0x212a, 0x212b, 0x2134, 0x2135, 0x2136, 0x2137, 0x2138,
            0x2139, 0x213a, 0x213b, 0x2140, 0x2141, 0x214f, 0x215f, 0x2160, 
            0x2164, 0x2167, 0x21a4, 0x21a6
        };

        for (int i : passL1) PID_LENGTH_MAP.put(i, 1);
        for (int i : passL2) PID_LENGTH_MAP.put(i, 2);
        for (int i : passL4) PID_LENGTH_MAP.put(i, 4);

        // Special Long PIDs
        PID_LENGTH_MAP.put(0x2166, 8);
        PID_LENGTH_MAP.put(0x2168, 8);
        PID_LENGTH_MAP.put(0x2187, 8);
        PID_LENGTH_MAP.put(0x2185, 10);
        PID_LENGTH_MAP.put(0x217f, 13);
    }

    public CastelProtocolDecoder(Protocol protocol) {
        super(protocol);
    }

    // ... Standard Castel Protocol Constants ...
    public static final short MSG_SC_LOGIN = 0x1001;
    public static final short MSG_SC_LOGIN_RESPONSE = (short) 0x9001;
    public static final short MSG_SC_LOGOUT = 0x1002;
    public static final short MSG_SC_HEARTBEAT = 0x1003;
    public static final short MSG_SC_HEARTBEAT_RESPONSE = (short) 0x9003;
    public static final short MSG_SC_GPS = 0x4001;
    public static final short MSG_SC_PID_DATA = 0x4002;
    public static final short MSG_SC_G_SENSOR = 0x4003;
    public static final short MSG_SC_SUPPORTED_PID = 0x4004;
    public static final short MSG_SC_OBD_DATA = 0x4005;
    public static final short MSG_SC_DTCS_PASSENGER = 0x4006;
    public static final short MSG_SC_DTCS_COMMERCIAL = 0x400B;
    public static final short MSG_SC_ALARM = 0x4007;
    public static final short MSG_SC_ALARM_RESPONSE = (short) 0xC007;
    public static final short MSG_SC_CELL = 0x4008;
    public static final short MSG_SC_GPS_SLEEP = 0x4009;
    public static final short MSG_SC_FUEL = 0x400E;
    public static final short MSG_SC_COMPREHENSIVE = 0x401F;
    public static final short MSG_SC_AGPS_REQUEST = 0x5101;
    public static final short MSG_SC_QUERY_RESPONSE = (short) 0xA002;
    public static final short MSG_SC_CURRENT_LOCATION = (short) 0xB001;

    public static final short MSG_CC_LOGIN = 0x4001;
    public static final short MSG_CC_LOGIN_RESPONSE = (short) 0x8001;
    public static final short MSG_CC_HEARTBEAT = 0x4206;
    public static final short MSG_CC_PETROL_CONTROL = 0x4583;
    public static final short MSG_CC_HEARTBEAT_RESPONSE = (short) 0x8206;

    private Position readPosition(DeviceSession deviceSession, ByteBuf buf) {

        Position position = new Position(getProtocolName());
        position.setDeviceId(deviceSession.getDeviceId());

        DateBuilder dateBuilder = new DateBuilder()
                .setDateReverse(buf.readUnsignedByte(), buf.readUnsignedByte(), buf.readUnsignedByte())
                .setTime(buf.readUnsignedByte(), buf.readUnsignedByte(), buf.readUnsignedByte());
        position.setTime(dateBuilder.getDate());

        double lat = buf.readUnsignedIntLE() / 3600000.0;
        double lon = buf.readUnsignedIntLE() / 3600000.0;
        position.setSpeed(UnitsConverter.knotsFromCps(buf.readUnsignedShortLE()));
        position.setCourse(buf.readUnsignedShortLE() * 0.1);

        int flags = buf.readUnsignedByte();
        if ((flags & 0x02) == 0) {
            lat = -lat;
        }
        if ((flags & 0x01) == 0) {
            lon = -lon;
        }
        position.setLatitude(lat);
        position.setLongitude(lon);
        position.setValid((flags & 0x0C) > 0);
        position.set(Position.KEY_SATELLITES, flags >> 4);

        return position;
    }

    private Position createPosition(DeviceSession deviceSession) {
        Position position = new Position(getProtocolName());
        position.setDeviceId(deviceSession.getDeviceId());
        getLastLocation(position, null);
        return position;
    }

    // --- CRITICAL FIX: UPDATED decodeObd METHOD ---
    private void decodeObd(Position position, ByteBuf buf, boolean groups) {

        int count = buf.readUnsignedByte();

        int[] pids = new int[count];
        for (int i = 0; i < count; i++) {
            // FIX: Removed "& 0xff" masking to allow 2-byte PIDs (e.g. 0x2103)
            pids[i] = buf.readUnsignedShortLE();
        }

        if (groups) {
            buf.readUnsignedByte(); // group count
            buf.readUnsignedByte(); // group size
        }

        for (int i = 0; i < count; i++) {
            int value = 0;
            
            // Safety: If we don't know the PID length, we must stop or the stream breaks.
            if (!PID_LENGTH_MAP.containsKey(pids[i])) {
                return;
            }

            int length = PID_LENGTH_MAP.get(pids[i]);
            
            // 1. READ THE VALUE
            if (length == 1) {
                value = buf.readUnsignedByte();
            } else if (length == 2) {
                value = buf.readUnsignedShortLE();
            } else if (length == 4) {
                value = buf.readIntLE();
            } else {
                // If data is too long (e.g. 8 bytes or strings), skip it.
                // We cannot save these as simple IO numbers.
                buf.skipBytes(length);
                continue; 
            }

            // 2. SAVE THE DATA (The "Force IO" Fix)
            // First, try to see if Traccar knows a standard name for it (like "rpm")
            Map.Entry<String, Object> entry = ObdDecoder.decodeData(pids[i], value, false);
            
            if (entry != null) {
                
                position.add(entry);
            } else {
                // It's a Commercial/Unknown PID, FORCE it to appear as io[PID]
                // This ensures io247, io224, etc. appear in your attributes
                position.set(Position.PREFIX_IO + pids[i], value);
            }
        }
    }

    private void decodeStat(Position position, ByteBuf buf) {
        buf.readUnsignedIntLE(); // ACC ON time
        buf.readUnsignedIntLE(); // UTC time
        position.set(Position.KEY_ODOMETER, buf.readUnsignedIntLE());
        position.set(Position.KEY_ODOMETER_TRIP, buf.readUnsignedIntLE());
        position.set(Position.KEY_FUEL_CONSUMPTION, buf.readUnsignedIntLE());
        buf.readUnsignedShortLE(); // current fuel consumption

        long state = buf.readUnsignedIntLE();
        position.addAlarm(BitUtil.check(state, 4) ? Position.ALARM_ACCELERATION : null);
        position.addAlarm(BitUtil.check(state, 5) ? Position.ALARM_BRAKING : null);
        position.addAlarm(BitUtil.check(state, 6) ? Position.ALARM_IDLE : null);
        position.set(Position.KEY_IGNITION, BitUtil.check(state, 2 * 8 + 2));
        position.set(Position.KEY_STATUS, state);

        buf.skipBytes(8);
    }

    private void sendResponse(
            Channel channel, SocketAddress remoteAddress,
            int version, ByteBuf id, short type, ByteBuf content) {

        if (channel != null) {
            int length = 2 + 2 + 1 + id.readableBytes() + 2 + 2 + 2;
            if (content != null) {
                length += content.readableBytes();
            }

            ByteBuf response = Unpooled.buffer(length);
            response.writeByte('@'); response.writeByte('@');
            response.writeShortLE(length);
            response.writeByte(version);
            response.writeBytes(id);
            response.writeShort(type);
            if (content != null) {
                response.writeBytes(content);
                content.release();
            }
            response.writeShortLE(
                    Checksum.crc16(Checksum.CRC16_X25, response.nioBuffer(0, response.writerIndex())));
            response.writeByte(0x0D); response.writeByte(0x0A);
            channel.writeAndFlush(new NetworkMessage(response, remoteAddress));
        }
    }

    private void sendResponse(
            Channel channel, SocketAddress remoteAddress, ByteBuf id, short type) {

        if (channel != null) {
            int length = 2 + 2 + id.readableBytes() + 2 + 4 + 8 + 2 + 2;

            ByteBuf response = Unpooled.buffer(length);
            response.writeByte('@'); response.writeByte('@');
            response.writeShortLE(length);
            response.writeBytes(id);
            response.writeShort(type);
            response.writeIntLE(0);
            for (int i = 0; i < 8; i++) {
                response.writeByte(0xff);
            }
            response.writeShortLE(
                    Checksum.crc16(Checksum.CRC16_X25, response.nioBuffer(0, response.writerIndex())));
            response.writeByte(0x0D); response.writeByte(0x0A);
            channel.writeAndFlush(new NetworkMessage(response, remoteAddress));
        }
    }

    private void decodeAlarm(Position position, int alarm) {
        switch (alarm) {
            case 0x01 -> position.addAlarm(Position.ALARM_OVERSPEED);
            case 0x02 -> position.addAlarm(Position.ALARM_LOW_POWER);
            case 0x03 -> position.addAlarm(Position.ALARM_TEMPERATURE);
            case 0x04 -> position.addAlarm(Position.ALARM_ACCELERATION);
            case 0x05 -> position.addAlarm(Position.ALARM_BRAKING);
            case 0x06 -> position.addAlarm(Position.ALARM_IDLE);
            case 0x07 -> position.addAlarm(Position.ALARM_TOW);
            case 0x08 -> position.addAlarm(Position.ALARM_HIGH_RPM);
            case 0x09 -> position.addAlarm(Position.ALARM_POWER_ON);
            case 0x0B -> position.addAlarm(Position.ALARM_LANE_CHANGE);
            case 0x0C -> position.addAlarm(Position.ALARM_CORNERING);
            case 0x0D -> position.addAlarm(Position.ALARM_FATIGUE_DRIVING);
            case 0x0E -> position.addAlarm(Position.ALARM_POWER_OFF);
            case 0x11 -> position.addAlarm(Position.ALARM_ACCIDENT);
            case 0x12 -> position.addAlarm(Position.ALARM_TAMPERING);
            case 0x16 -> position.set(Position.KEY_IGNITION, true);
            case 0x17 -> position.set(Position.KEY_IGNITION, false);
            case 0x1C -> position.addAlarm(Position.ALARM_VIBRATION);
        }
    }

    private Object decodeSc(
            Channel channel, SocketAddress remoteAddress, ByteBuf buf,
            int version, ByteBuf id, short type, DeviceSession deviceSession) {

        Position position = null;
        int count;

        switch (type) {

            case MSG_SC_HEARTBEAT:
                sendResponse(channel, remoteAddress, version, id, MSG_SC_HEARTBEAT_RESPONSE, null);
                return null;

            case MSG_SC_LOGIN:
            case MSG_SC_LOGOUT:
            case MSG_SC_GPS:
            case MSG_SC_ALARM:
            case MSG_SC_CURRENT_LOCATION:
            case MSG_SC_FUEL:
            case MSG_SC_COMPREHENSIVE:
                if (type == MSG_SC_LOGIN) {
                    ByteBuf response = Unpooled.buffer(10);
                    response.writeIntLE(0xFFFFFFFF);
                    response.writeShortLE(0);
                    response.writeIntLE((int) (System.currentTimeMillis() / 1000));
                    sendResponse(channel, remoteAddress, version, id, MSG_SC_LOGIN_RESPONSE, response);
                } else if (type == MSG_SC_GPS || type == MSG_SC_COMPREHENSIVE) {
                    buf.readUnsignedByte(); // historical
                    if (type == MSG_SC_COMPREHENSIVE) {
                        buf.readUnsignedIntLE(); // index
                    }
                } else if (type == MSG_SC_ALARM) {
                    ByteBuf response = Unpooled.buffer(10);
                    response.writeIntLE(buf.readIntLE()); // alarm index
                    sendResponse(channel, remoteAddress, version, id, MSG_SC_ALARM_RESPONSE, response);
                } else if (type == MSG_SC_CURRENT_LOCATION) {
                    buf.readUnsignedShortLE();
                }

                buf.readUnsignedIntLE(); // ACC ON time
                buf.readUnsignedIntLE(); // UTC time
                long odometer = buf.readUnsignedIntLE();
                long tripOdometer = buf.readUnsignedIntLE();
                long fuelConsumption = buf.readUnsignedIntLE();
                buf.readUnsignedShortLE(); // current fuel consumption
                long status = buf.readUnsignedIntLE();
                buf.skipBytes(8);

                count = buf.readUnsignedByte();

                List<Position> positions = new LinkedList<>();

                for (int i = 0; i < count; i++) {
                    position = readPosition(deviceSession, buf);
                    position.set(Position.KEY_ODOMETER, odometer);
                    position.set(Position.KEY_ODOMETER_TRIP, tripOdometer);
                    position.set(Position.KEY_FUEL_CONSUMPTION, fuelConsumption);
                    position.set(Position.KEY_STATUS, status);
                    positions.add(position);
                }

                if (type == MSG_SC_ALARM) {
                    int alarmCount = buf.readUnsignedByte();
                    for (int i = 0; i < alarmCount; i++) {
                        if (buf.readUnsignedByte() != 0) { // Alarm active flag
                            int event = buf.readUnsignedByte();
                            
                            // 1. READ THE VALUE (Correctly reading the 2-byte description)
                            int description = buf.readUnsignedShortLE(); // This contains Speed or G-Force
                            int threshold = buf.readUnsignedShortLE();   // The limit that was broken
                            
                            for (Position p : positions) {
                                decodeAlarm(p, event);
                                
                                // 2. SAVE EXTRA DATA based on event type
                                switch (event) {
                                    case 0x04: // Hard Acceleration
                                    case 0x05: // Hard Braking
                                    case 0x0B: // Lane Change
                                    case 0x0C: // Sharp Turn
                                        // High byte often contains G-value (unit 0.1g) or Speed depending on model
                                        int highByte = (description >> 8) & 0xFF;
                                        if (highByte != 0xFF) {
                                            // Store the intensity (e.g., 5 means 0.5g)
                                            p.set("eventIntensity", highByte * 0.1); 
                                        }
                                        break;
                                        
                                    case 0x11: // Crash
                                        // Low byte indicates direction: 00=Front, 01=Back, 02=Left, 03=Right
                                        int direction = description & 0xFF;
                                        String dirStr = switch(direction) {
                                            case 0 -> "Front";
                                            case 1 -> "Back";
                                            case 2 -> "Left";
                                            case 3 -> "Right";
                                            default -> "Unknown";
                                        };
                                        p.set("crashDirection", dirStr);
                                        break;
                                }
                            }
                        }
                    }
                } else if (type == MSG_SC_FUEL) {
                    for (Position p : positions) {
                        p.set(Position.PREFIX_ADC + 1, buf.readUnsignedShortLE());
                    }
                } else if (type == MSG_SC_COMPREHENSIVE) {
                    if (position == null) {
                        position = new Position(getProtocolName());
                        position.setDeviceId(deviceSession.getDeviceId());
                        getLastLocation(position, null);
                    }

                    while (buf.readableBytes() > 4) {
                        int tag = buf.readUnsignedShortLE();
                        int length = buf.readUnsignedShortLE();
                        switch (tag) {
                            case 0x0002 -> {
                                int pidCount = buf.readUnsignedByte();
                                for (int i = 0; i < pidCount; i++) {
                                    int pidTag = buf.readUnsignedShortLE();
                                    int pidLength = buf.readUnsignedShortLE();
                                    position.set("pid" + pidTag, ByteBufUtil.hexDump(buf.readSlice(pidLength)));
                                }
                            }
                            case 0x0004 -> buf.skipBytes(length); // supported data streams
                            case 0x0005 -> buf.skipBytes(length); // snapshot data
                            case 0x0006 -> {
                                buf.readUnsignedByte(); // fault flag
                                int faultCount = buf.readUnsignedByte();
                                for (int i = 1; i <= faultCount; i++) {
                                    position.set("fault" + i, buf.readUnsignedShortLE());
                                }
                            }
                            case 0x0007 -> {
                                buf.readUnsignedIntLE(); // alarm index
                                int alarmCount = buf.readUnsignedByte();
                                for (int i = 0; i < alarmCount; i++) {
                                    int alarmFlag = buf.readUnsignedByte();
                                    int event = buf.readUnsignedByte();
                                    if (alarmFlag > 0) {
                                        decodeAlarm(position, event);
                                    }
                                    buf.readUnsignedShortLE(); // description
                                    buf.readUnsignedShortLE(); // threshold
                                }
                            }
                            case 0x000B -> {
                                buf.readUnsignedByte(); // fault flag
                                int faultCount = buf.readUnsignedByte();
                                for (int i = 1; i <= faultCount; i++) {
                                    position.set("fault" + i, buf.readUnsignedIntLE());
                                }
                                buf.readUnsignedShortLE(); // mil status
                            }
                            case 0x0010 -> position.set(Position.KEY_DEVICE_TEMP, buf.readShortLE() / 10.0);
                            case 0x0011, 0x0012, 0x0013, 0x0014 ->
                                    position.set(Position.PREFIX_TEMP + (tag - 0x0010), buf.readShortLE() / 10.0);
                            case 0x0020 -> position.set(Position.KEY_POWER, buf.readUnsignedShortLE() / 100.0);
                            case 0x0021 -> position.set(Position.KEY_BATTERY, buf.readUnsignedShortLE() / 100.0);
                            default -> buf.skipBytes(length);
                        }
                    }
                }

                return positions.isEmpty() ? null : positions;

            case MSG_SC_GPS_SLEEP:
                buf.readUnsignedIntLE(); // device time
                return readPosition(deviceSession, buf);

            case MSG_SC_AGPS_REQUEST:
                return readPosition(deviceSession, buf);

            case MSG_SC_PID_DATA:
                position = createPosition(deviceSession);

                decodeStat(position, buf);

                buf.readUnsignedShortLE(); // sample rate
                decodeObd(position, buf, true);

                return position;

            case MSG_SC_G_SENSOR:
                position = createPosition(deviceSession);

                decodeStat(position, buf);

                buf.readUnsignedShortLE(); // sample rate

                count = buf.readUnsignedByte();

                StringBuilder data = new StringBuilder("[");
                for (int i = 0; i < count; i++) {
                    if (i > 0) {
                        data.append(",");
                    }
                    data.append("[");
                    data.append(buf.readShortLE() * 0.015625);
                    data.append(",");
                    data.append(buf.readShortLE() * 0.015625);
                    data.append(",");
                    data.append(buf.readShortLE() * 0.015625);
                    data.append("]");
                }
                data.append("]");

                position.set(Position.KEY_G_SENSOR, data.toString());

                return position;

            case MSG_SC_DTCS_PASSENGER:
            case MSG_SC_DTCS_COMMERCIAL:
                position = createPosition(deviceSession);

                decodeStat(position, buf);

                buf.readUnsignedByte(); // flag

                count = buf.readUnsignedByte();
                StringBuilder codes = new StringBuilder();
                for (int i = 0; i < count; i++) {
                    if (type == MSG_SC_DTCS_COMMERCIAL) {
                        codes.append(ObdDecoder.decodeCode(buf.readUnsignedShortLE()));
                        buf.readUnsignedByte(); // attribute
                        buf.readUnsignedByte(); // occurrence
                    } else {
                        codes.append(ObdDecoder.decodeCode(buf.readUnsignedShortLE()));
                    }
                    codes.append(' ');
                }
                position.set(Position.KEY_DTCS, codes.toString().trim());

                return position;

            case MSG_SC_OBD_DATA:
                position = createPosition(deviceSession);

                decodeStat(position, buf);

                buf.readUnsignedByte(); // flag
                decodeObd(position, buf, false);

                return position;

            case MSG_SC_CELL:
                position = createPosition(deviceSession);

                decodeStat(position, buf);

                position.setNetwork(new Network(
                        CellTower.fromLacCid(getConfig(), buf.readUnsignedShortLE(), buf.readUnsignedShortLE())));

                return position;

            case MSG_SC_QUERY_RESPONSE:
                position = createPosition(deviceSession);

                buf.readUnsignedShortLE(); // index
                buf.readUnsignedByte(); // response count
                buf.readUnsignedByte(); // response index

                int failureCount = buf.readUnsignedByte();
                for (int i = 0; i < failureCount; i++) {
                    buf.readUnsignedShortLE(); // tag
                }

                int successCount = buf.readUnsignedByte();
                for (int i = 0; i < successCount; i++) {
                    buf.readUnsignedShortLE(); // tag
                    position.set(Position.KEY_RESULT,
                            buf.readSlice(buf.readUnsignedShortLE()).toString(StandardCharsets.US_ASCII));
                }

                return position;

            default:
                return null;

        }
    }

    private Object decodeCc(
            Channel channel, SocketAddress remoteAddress, ByteBuf buf,
            int version, ByteBuf id, short type, DeviceSession deviceSession) {

        if (type == MSG_CC_HEARTBEAT) {

            sendResponse(channel, remoteAddress, version, id, MSG_CC_HEARTBEAT_RESPONSE, null);

            buf.readUnsignedByte(); // 0x01 for history
            int count = buf.readUnsignedByte();

            List<Position> positions = new LinkedList<>();

            for (int i = 0; i < count; i++) {
                Position position = readPosition(deviceSession, buf);

                position.set(Position.KEY_STATUS, buf.readUnsignedIntLE());
                position.set(Position.KEY_BATTERY, buf.readUnsignedByte());
                position.set(Position.KEY_ODOMETER, buf.readUnsignedIntLE());

                buf.readUnsignedByte(); // geo-fencing id
                buf.readUnsignedByte(); // geo-fencing flags
                buf.readUnsignedByte(); // additional flags

                position.setNetwork(new Network(
                        CellTower.fromLacCid(getConfig(), buf.readUnsignedShortLE(), buf.readUnsignedShortLE())));

                positions.add(position);
            }

            return positions;

        } else if (type == MSG_CC_LOGIN) {

            sendResponse(channel, remoteAddress, version, id, MSG_CC_LOGIN_RESPONSE, null);

            Position position = readPosition(deviceSession, buf);

            position.set(Position.KEY_STATUS, buf.readUnsignedIntLE());
            position.set(Position.KEY_BATTERY, buf.readUnsignedByte());
            position.set(Position.KEY_ODOMETER, buf.readUnsignedIntLE());

            buf.readUnsignedByte(); // geo-fencing id
            buf.readUnsignedByte(); // geo-fencing flags
            buf.readUnsignedByte(); // additional flags

            // GSM_CELL_CODE
            // STR_Z - firmware version
            // STR_Z - hardware version

            return position;

        }

        return null;
    }

    private Object decodeMpip(
            Channel channel, SocketAddress remoteAddress, ByteBuf buf,
            int version, ByteBuf id, short type, DeviceSession deviceSession) {

        if (type == 0x4001) {

            sendResponse(channel, remoteAddress, version, id, type, null);

            return readPosition(deviceSession, buf);

        } else if (type == 0x2001) {

            sendResponse(channel, remoteAddress, id, (short) 0x1001);

            buf.readUnsignedIntLE(); // index
            buf.readUnsignedIntLE(); // unix time
            buf.readUnsignedByte();

            return readPosition(deviceSession, buf);

        } else if (type == 0x4201 || type == 0x4202 || type == 0x4206) {

            return readPosition(deviceSession, buf);

        } else if (type == 0x4204) {

            List<Position> positions = new LinkedList<>();

            for (int i = 0; i < 8; i++) {
                Position position = readPosition(deviceSession, buf);
                buf.skipBytes(31);
                positions.add(position);
            }

            return positions;

        }

        return null;
    }

    @Override
    protected Object decode(
            Channel channel, SocketAddress remoteAddress, Object msg) throws Exception {

        ByteBuf buf = (ByteBuf) msg;

        int header = buf.readUnsignedShortLE();
        buf.readUnsignedShortLE(); // length

        int version = -1;
        if (header == 0x4040) {
            version = buf.readUnsignedByte();
        }

        ByteBuf id = buf.readSlice(20);
        short type = buf.readShort();

        DeviceSession deviceSession = getDeviceSession(
                channel, remoteAddress, id.toString(StandardCharsets.US_ASCII).trim());
        if (deviceSession == null) {
            return null;
        }

        return switch (version) {
            case -1 -> decodeMpip(channel, remoteAddress, buf, version, id, type, deviceSession);
            case 3, 4 -> decodeSc(channel, remoteAddress, buf, version, id, type, deviceSession);
            default -> decodeCc(channel, remoteAddress, buf, version, id, type, deviceSession);
        };
    }

}