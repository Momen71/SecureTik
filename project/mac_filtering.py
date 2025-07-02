import sqlite3
import subprocess

def block_mac(mac_address, reason="Manual block"):
    """Block MAC address on both INPUT and FORWARD chains"""
    conn = None
    try:
        # Clean any existing rules first
        subprocess.run(
            ['sudo', 'iptables', '-D', 'INPUT', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'],
            stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ['sudo', 'iptables', '-D', 'FORWARD', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'],
            stderr=subprocess.DEVNULL
        )
        
        # Add new blocking rules
        subprocess.run(
            ['sudo', 'iptables', '-A', 'INPUT', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'],
            check=True
        )
        subprocess.run(
            ['sudo', 'iptables', '-A', 'FORWARD', '-i', 'eth0', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'],
            check=True
        )
        
        # Update database
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO blocked_mac (mac, reason) VALUES (?, ?)", 
                 (mac_address, reason))
        conn.commit()
        return True
        
    except Exception as e:
        print(f"Error blocking MAC: {str(e)}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def unblock_mac(mac_address):
    """Unblock MAC address"""
    conn = None
    try:
        # Remove iptables rules
        subprocess.run(
            ['sudo', 'iptables', '-D', 'INPUT', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'],
            stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ['sudo', 'iptables', '-D', 'FORWARD', '-m', 'mac', '--mac-source', mac_address, '-j', 'DROP'],
            stderr=subprocess.DEVNULL
        )
        
        # Remove from database
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("DELETE FROM blocked_mac WHERE mac=?", (mac_address,))
        conn.commit()
        return True
        
    except Exception as e:
        print(f"Error unblocking MAC: {str(e)}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()
