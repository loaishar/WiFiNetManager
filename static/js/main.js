document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Content Loaded');
    
    const scanButton = document.getElementById('scan-button');
    if (scanButton) {
        scanButton.addEventListener('click', function() {
            const button = this;
            const originalText = button.innerHTML;
            button.disabled = true;
            button.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Scanning...';
            
            console.log('Starting network scan...');
            
            const resetButton = () => {
                button.disabled = false;
                button.innerHTML = originalText;
            };

            fetchWithAuth('/api/scan', { 
                method: 'POST',
                timeout: 10000 // 10 second timeout
            })
            .then(response => response.json())
            .then(data => {
                console.log('Scan response:', data);
                if (data.success) {
                    if (data.devices && data.devices.length > 0) {
                        console.log(`Found ${data.devices.length} devices`);
                        refreshDeviceList(data.devices);
                    } else {
                        console.log('No devices found');
                        document.getElementById('device-list').innerHTML = 
                            '<tr><td colspan="6">No devices found on the network. Please check your network connection.</td></tr>';
                    }
                } else {
                    throw new Error(data.message || 'Error scanning for devices');
                }
            })
            .catch(error => {
                console.error('Scan error:', error);
                alert(error.message || 'Error scanning for devices. Please try again.');
                document.getElementById('device-list').innerHTML = 
                    '<tr><td colspan="6">Error scanning for devices. Please try again.</td></tr>';
            })
            .finally(() => {
                console.log('Scan completed');
                resetButton();
            });
        });
    }

    // Handle device updates via WebSocket
    const socket = io();
    socket.on('devices_update', function(devices) {
        refreshDeviceList(devices);
    });

    // Handle device toggling
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('toggle-device')) {
            const deviceId = e.target.dataset.deviceId;
            e.target.disabled = true;
            
            fetchWithAuth(`/api/devices/${deviceId}/toggle`, { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (!data.success) {
                        throw new Error('Failed to toggle device');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error toggling device. Please try again.');
                })
                .finally(() => {
                    e.target.disabled = false;
                });
        }
    });

    function refreshDeviceList(devices) {
        const deviceList = document.getElementById('device-list');
        if (!deviceList) return;
        
        if (!devices || devices.length === 0) {
            deviceList.innerHTML = '<tr><td colspan="6">No devices found. Try scanning for new devices.</td></tr>';
        } else {
            deviceList.innerHTML = '';
            devices.forEach(device => {
                const row = document.createElement('tr');
                row.id = `device-${device.id}`;
                row.innerHTML = `
                    <td>${device.name}</td>
                    <td>${device.ip_address}</td>
                    <td>${device.mac_address}</td>
                    <td>${device.status ? 'Online' : 'Offline'}</td>
                    <td>${device.last_seen}</td>
                    <td>
                        <button class="btn ${device.blocked ? 'btn-success' : 'btn-danger'} btn-sm toggle-device" data-device-id="${device.id}">
                            ${device.blocked ? 'Unblock' : 'Block'}
                        </button>
                    </td>
                `;
                deviceList.appendChild(row);
            });
        }
    }
});
