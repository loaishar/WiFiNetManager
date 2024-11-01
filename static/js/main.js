// Update the updateDeviceInList function to remove data_usage
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

// Update the refreshDeviceList function to remove data_usage
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
