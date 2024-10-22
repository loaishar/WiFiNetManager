function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function checkAuthentication() {
    const token = getCookie('access_token_cookie');
    if (!token) {
        window.location.href = '/login';
    }
}

function fetchWithAuth(url, options = {}) {
    options.credentials = 'include';

    return fetch(url, options)
        .then(response => {
            if (response.status === 401) {
                console.log('Token expired, attempting to refresh');
                return fetch('/refresh', { method: 'POST', credentials: 'include' })
                    .then(refreshResponse => {
                        if (!refreshResponse.ok) {
                            throw new Error('Token refresh failed');
                        }
                        return refreshResponse.json();
                    })
                    .then(data => {
                        console.log('Token refreshed successfully');
                        options.headers = options.headers || {};
                        options.headers['Authorization'] = `Bearer ${data.access_token}`;
                        return fetch(url, options);
                    })
                    .catch(refreshError => {
                        console.error('Error refreshing token:', refreshError);
                        window.location.href = '/login';
                        throw refreshError;
                    });
            }
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response;
        });
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Content Loaded');
    checkAuthentication();

    const deviceList = document.getElementById('device-list');
    const scanButton = document.getElementById('scan-button');
    const loadingIndicator = document.getElementById('loading-indicator');

    let socket;

    function initializeSocket() {
        console.log('Initializing Socket.IO');

        const token = getCookie('access_token_cookie');
        const socketUrl = window.location.origin;

        console.log('Connecting to WebSocket URL:', socketUrl);

        socket = io(socketUrl, {
            transports: ['websocket'],
            auth: {
                token: token
            },
            reconnection: true,
            reconnectionAttempts: 5
        });

        socket.on('connect', function() {
            console.log('Connected to WebSocket server');
        });

        socket.on('disconnect', function(reason) {
            console.log('Disconnected from WebSocket server:', reason);
            if (reason === 'io server disconnect') {
                socket.auth.token = getCookie('access_token_cookie');
                socket.connect();
            }
        });

        socket.on('connect_error', function(error) {
            console.error('Connection error:', error.message);
            if (error.message === 'Unauthorized') {
                fetch('/refresh', { method: 'POST', credentials: 'include' })
                    .then(refreshResponse => {
                        if (!refreshResponse.ok) {
                            throw new Error('Token refresh failed');
                        }
                        return refreshResponse.json();
                    })
                    .then(data => {
                        socket.auth.token = data.access_token;
                        socket.connect();
                    })
                    .catch(refreshError => {
                        console.error('Error refreshing token:', refreshError);
                        window.location.href = '/login';
                    });
            }
        });

        socket.on('device_updated', function(device) {
            console.log('Device update received:', device);
            updateDeviceInList(device);
        });

        socket.on('devices_update', function(devices) {
            console.log('Devices update received:', devices);
            refreshDeviceList(devices);
        });

        socket.on('error', function(error) {
            console.error('WebSocket error:', error);
            if (error.message === 'Unauthorized') {
                window.location.href = '/login';
            }
        });
    }

    initializeSocket();

    function showLoading() {
        if (loadingIndicator) {
            loadingIndicator.style.display = 'block';
        }
    }

    function hideLoading() {
        if (loadingIndicator) {
            loadingIndicator.style.display = 'none';
        }
    }

    function updateDeviceInList(device) {
        const deviceRow = document.getElementById(`device-${device.id}`);
        if (deviceRow) {
            deviceRow.innerHTML = `
                <td>${device.name}</td>
                <td>${device.ip_address}</td>
                <td>${device.mac_address}</td>
                <td>${device.status ? 'Online' : 'Offline'}</td>
                <td>${device.last_seen}</td>
                <td>${(device.data_usage / 1024 / 1024).toFixed(2)} MB</td>
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

    function refreshDeviceList(devices) {
        if (!deviceList) return;
        
        if (devices.length === 0) {
            deviceList.innerHTML = '<tr><td colspan="7">No devices found. Try scanning for new devices.</td></tr>';
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
                    <td>${(device.data_usage / 1024 / 1024).toFixed(2)} MB</td>
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

    function loadDevices() {
        showLoading();
        fetchWithAuth('/api/devices')
            .then(response => response.json())
            .then(devices => {
                refreshDeviceList(devices);
                hideLoading();
            })
            .catch(error => {
                console.error('Error fetching devices:', error);
                if (deviceList) {
                    deviceList.innerHTML = '<tr><td colspan="7">Error loading devices. Please try again.</td></tr>';
                }
                hideLoading();
            });
    }

    if (scanButton) {
        scanButton.addEventListener('click', function() {
            showLoading();
            fetchWithAuth('/api/scan', { method: 'POST' })
                .then(response => response.json())
                .then(result => {
                    if (result.success) {
                        loadDevices();
                    } else {
                        console.error('Scan failed:', result.error);
                        if (deviceList) {
                            deviceList.innerHTML = '<tr><td colspan="7">Scan failed. Please try again.</td></tr>';
                        }
                    }
                    hideLoading();
                })
                .catch(error => {
                    console.error('Error during scan:', error);
                    if (deviceList) {
                        deviceList.innerHTML = '<tr><td colspan="7">Error during scan. Please try again.</td></tr>';
                    }
                    hideLoading();
                });
        });
    }

    loadDevices();

    if (deviceList) {
        deviceList.addEventListener('click', function(event) {
            if (event.target.classList.contains('toggle-device')) {
                const deviceId = event.target.getAttribute('data-device-id');
                toggleDevice(deviceId);
            }
        });
    }

    // Network Usage Chart
    const ctx = document.getElementById('networkUsageChart');
    if (ctx) {
        fetchWithAuth('/api/network_usage')
            .then(response => response.json())
            .then(data => {
                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: data.labels,
                        datasets: [{
                            label: 'Network Usage (MB)',
                            data: data.values,
                            borderColor: 'rgb(75, 192, 192)',
                            tension: 0.1
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            x: {
                                title: {
                                    display: true,
                                    text: 'Time'
                                }
                            },
                            y: {
                                title: {
                                    display: true,
                                    text: 'Usage (MB)'
                                },
                                beginAtZero: true
                            }
                        }
                    }
                });
            })
            .catch(error => {
                console.error('Error fetching network usage data:', error);
            });
    }
});

function toggleDevice(deviceId) {
    fetchWithAuth(`/api/devices/${deviceId}/toggle`, { method: 'POST' })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                console.log(`Device ${deviceId} toggled successfully`);
            } else {
                console.error('Error toggling device:', result.error);
            }
        })
        .catch(error => {
            console.error('Error toggling device:', error);
        });
}
