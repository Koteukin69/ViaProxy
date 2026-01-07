/*
 * This file is part of ViaProxy - https://github.com/RaphiMC/ViaProxy
 * Copyright (C) 2021-2026 RK_01/RaphiMC and contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.raphimc.viaproxy.proxy.security;

import net.raphimc.viaproxy.ViaProxy;
import net.raphimc.viaproxy.util.logging.Logger;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages IP whitelist for ViaProxy connections.
 * Supports both individual IP addresses and CIDR notation.
 */
public class IPWhitelistManager {

    private static final List<IPEntry> whitelist = new ArrayList<>();

    /**
     * Loads the IP whitelist from configuration
     */
    public static void loadWhitelist() {
        whitelist.clear();

        if (!ViaProxy.getConfig().isIpWhitelistEnabled()) {
            return;
        }

        List<String> rawList = ViaProxy.getConfig().getIpWhitelist();
        if (rawList == null || rawList.isEmpty()) {
            Logger.LOGGER.warn("IP whitelist is enabled but no IP addresses are configured!");
            return;
        }

        for (String entry : rawList) {
            try {
                whitelist.add(parseIPEntry(entry));
            } catch (Exception e) {
                Logger.LOGGER.error("Failed to parse IP whitelist entry '" + entry + "': " + e.getMessage());
            }
        }

        Logger.LOGGER.info("Loaded " + whitelist.size() + " IP whitelist entries");
    }

    /**
     * Checks if an IP address is allowed to connect
     *
     * @param address The socket address to check
     * @return true if the IP is allowed, false otherwise
     */
    public static boolean isAllowed(InetSocketAddress address) {
        if (!ViaProxy.getConfig().isIpWhitelistEnabled()) {
            return true;
        }

        if (whitelist.isEmpty()) {
            Logger.LOGGER.warn("IP whitelist is enabled but empty - blocking connection from " + address.getAddress().getHostAddress());
            return false;
        }

        InetAddress ip = address.getAddress();

        for (IPEntry entry : whitelist) {
            if (entry.matches(ip)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parses an IP entry string into an IPEntry object
     * Supports both individual IPs and CIDR notation
     */
    private static IPEntry parseIPEntry(String entry) throws UnknownHostException {
        entry = entry.trim();

        if (entry.contains("/")) {
            // CIDR notation
            String[] parts = entry.split("/");
            InetAddress network = InetAddress.getByName(parts[0]);
            int prefixLength = Integer.parseInt(parts[1]);
            return new CIDREntry(network, prefixLength);
        } else {
            // Single IP
            InetAddress ip = InetAddress.getByName(entry);
            return new SingleIPEntry(ip);
        }
    }

    /**
     * Base interface for IP entries
     */
    private interface IPEntry {
        boolean matches(InetAddress address);
    }

    /**
     * Single IP address entry
     */
    private static class SingleIPEntry implements IPEntry {
        private final InetAddress ip;

        public SingleIPEntry(InetAddress ip) {
            this.ip = ip;
        }

        @Override
        public boolean matches(InetAddress address) {
            return ip.equals(address);
        }
    }

    /**
     * CIDR notation entry (e.g., 192.168.1.0/24)
     */
    private static class CIDREntry implements IPEntry {
        private final byte[] network;
        private final byte[] mask;

        public CIDREntry(InetAddress network, int prefixLength) {
            this.network = network.getAddress();
            this.mask = createMask(prefixLength, this.network.length);
        }

        @Override
        public boolean matches(InetAddress address) {
            byte[] addr = address.getAddress();

            // Different IP versions don't match
            if (addr.length != network.length) {
                return false;
            }

            // Check if address is in network
            for (int i = 0; i < addr.length; i++) {
                if ((addr[i] & mask[i]) != (network[i] & mask[i])) {
                    return false;
                }
            }

            return true;
        }

        /**
         * Creates a subnet mask from prefix length
         */
        private static byte[] createMask(int prefixLength, int bytes) {
            byte[] mask = new byte[bytes];

            for (int i = 0; i < mask.length; i++) {
                if (prefixLength >= 8) {
                    mask[i] = (byte) 0xFF;
                    prefixLength -= 8;
                } else if (prefixLength > 0) {
                    mask[i] = (byte) (0xFF << (8 - prefixLength));
                    prefixLength = 0;
                } else {
                    mask[i] = 0;
                }
            }

            return mask;
        }
    }
}
