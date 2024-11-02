// Update the scan button functionality
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Content Loaded');
    
    const scanButton = document.getElementById('scan-button');
    if (scanButton) {
        scanButton.addEventListener('click', function() {
            this.disabled = true;
            this.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Scanning...';
            
            fetchWithAuth('/api/scan', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        refreshDeviceList(data.devices);
                    } else {
                        alert(data.message || 'Error scanning for devices');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error scanning for devices. Please try again.');
                })
                .finally(() => {
                    this.disabled = false;
                    this.innerHTML = 'Scan for new devices';
                });
        });
    }

    // Existing updateDeviceInList function
    function updateDeviceInList(device) {
        const deviceRow = document.getElementById(`device-${device.id}`);
        if (deviceRow) {
            deviceRow.innerHTML = `
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
        } else {
            refreshDeviceList([device]);
        }
    }

    // Existing refreshDeviceList function
    function refreshDeviceList(devices) {
        const deviceList = document.getElementById('device-list');
        if (!deviceList) return;
        
        if (devices.length === 0) {
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
