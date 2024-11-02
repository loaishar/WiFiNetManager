document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Content Loaded');
    
    const scanButton = document.getElementById('scan-button');
    if (scanButton) {
        scanButton.addEventListener('click', function() {
            this.disabled = true;
            const originalText = this.innerHTML;
            this.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Scanning...';
            
            fetchWithAuth('/api/scan', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        if (data.devices && data.devices.length > 0) {
                            refreshDeviceList(data.devices);
                        } else {
                            document.getElementById('device-list').innerHTML = 
                                '<tr><td colspan="6">No devices found on the network. Please check your network connection.</td></tr>';
                        }
                    } else {
                        throw new Error(data.message || 'Error scanning for devices');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert(error.message || 'Error scanning for devices. Please try again.');
                    document.getElementById('device-list').innerHTML = 
                        '<tr><td colspan="6">Error scanning for devices. Please try again.</td></tr>';
                })
                .finally(() => {
                    this.disabled = false;
                    this.innerHTML = originalText;
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
