// Admin Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // Network Settings
    const saveSettingBtn = document.getElementById('saveSettingBtn');
    if (saveSettingBtn) {
        saveSettingBtn.addEventListener('click', function() {
            const name = document.getElementById('settingName').value;
            const value = document.getElementById('settingValue').value;
            const description = document.getElementById('settingDescription').value;

            fetchWithAuth('/api/admin/settings', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ name, value, description })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Error saving setting');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error saving setting');
            });
        });
    }

    // Delete Setting
    document.querySelectorAll('.delete-setting').forEach(button => {
        button.addEventListener('click', function() {
            const settingId = this.dataset.settingId;
            if (confirm('Are you sure you want to delete this setting?')) {
                fetchWithAuth(`/api/admin/settings/${settingId}`, {
                    method: 'DELETE'
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        location.reload();
                    } else {
                        alert('Error deleting setting');
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    alert('Error deleting setting');
                });
            }
        });
    });

    // Edit Device
    document.querySelectorAll('.edit-device').forEach(button => {
        button.addEventListener('click', function() {
            const deviceId = this.dataset.deviceId;
            const row = this.closest('tr');
            
            document.getElementById('deviceId').value = deviceId;
            document.getElementById('deviceName').value = row.cells[0].textContent;
            document.getElementById('bandwidthLimit').value = row.cells[5].textContent.trim() === 'Unlimited' 
                ? 0 
                : parseInt(row.cells[5].textContent);
            document.getElementById('deviceNotes').value = row.cells[6].textContent;
        });
    });

    // Save Device Changes
    const saveDeviceBtn = document.getElementById('saveDeviceBtn');
    if (saveDeviceBtn) {
        saveDeviceBtn.addEventListener('click', function() {
            const deviceId = document.getElementById('deviceId').value;
            const name = document.getElementById('deviceName').value;
            const bandwidthLimit = parseInt(document.getElementById('bandwidthLimit').value);
            const notes = document.getElementById('deviceNotes').value;

            fetchWithAuth(`/api/admin/devices/${deviceId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    name, 
                    bandwidth_limit: bandwidthLimit,
                    notes 
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('Error updating device');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error updating device');
            });
        });
    }

    // Initialize Socket.IO for real-time updates
    const socket = io();
    
    socket.on('device_updated', function(device) {
        const row = document.querySelector(`tr[data-device-id="${device.id}"]`);
        if (row) {
            updateDeviceRow(row, device);
        }
    });

    function updateDeviceRow(row, device) {
        row.cells[0].textContent = device.name;
        row.cells[4].textContent = `${(device.data_usage / (1024 * 1024)).toFixed(2)} MB`;
        row.cells[5].textContent = device.bandwidth_limit === 0 ? 'Unlimited' : `${device.bandwidth_limit} Mbps`;
        row.cells[6].textContent = device.notes || '';
        
        const statusBadge = row.cells[3].querySelector('.badge');
        statusBadge.className = `badge bg-${device.status ? 'success' : 'danger'}`;
        statusBadge.textContent = device.status ? 'Online' : 'Offline';
        
        const toggleButton = row.querySelector('.toggle-device');
        toggleButton.className = `btn btn-sm btn-${device.blocked ? 'success' : 'danger'} toggle-device`;
        toggleButton.textContent = device.blocked ? 'Unblock' : 'Block';
    }
});
