let socket;

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function checkAuthentication() {
    console.log('Checking authentication on path:', window.location.pathname);
    const token = getCookie('access_token_cookie');
    console.log('Token found:', token ? 'Yes' : 'No');
    
    const isLoginPage = window.location.pathname === '/login';
    const isRegisterPage = window.location.pathname === '/register';
    const isHomePage = window.location.pathname === '/';
    
    if (isLoginPage || isRegisterPage || isHomePage) {
        console.log('On public page, no authentication needed');
        return true;
    }
    
    if (!token) {
        console.log('No token found, redirecting to login');
        window.location.href = '/login';
        return false;
    }
    
    console.log('Token found, authentication successful');
    return true;
}

function fetchWithAuth(url, options = {}) {
    console.log('Fetching with auth:', url);
    options.credentials = 'include';

    return fetch(url, options)
        .then(response => {
            console.log('Response status:', response.status);
            if (response.status === 401) {
                console.log('Token expired, attempting to refresh');
                return fetch('/refresh', { 
                    method: 'POST', 
                    credentials: 'include'
                })
                .then(refreshResponse => {
                    console.log('Refresh response status:', refreshResponse.status);
                    if (!refreshResponse.ok) {
                        throw new Error('Token refresh failed');
                    }
                    return refreshResponse.json();
                })
                .then(() => {
                    console.log('Token refreshed successfully');
                    return fetch(url, options);
                })
                .catch(refreshError => {
                    console.error('Error refreshing token:', refreshError);
                    if (window.location.pathname !== '/login') {
                        window.location.href = '/login';
                    }
                    throw refreshError;
                });
            }
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response;
        });
}

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
                .then(() => {
                    socket.auth.token = getCookie('access_token_cookie');
                    socket.connect();
                })
                .catch(() => {
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
}

function loadDevices() {
    const deviceList = document.getElementById('device-list');
    if (!deviceList) return;
    
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

function showLoading() {
    const loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'block';
    }
}

function hideLoading() {
    const loadingIndicator = document.getElementById('loading-indicator');
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
            <td>${(device.data_usage / (1024 * 1024)).toFixed(2)} MB</td>
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
    const deviceList = document.getElementById('device-list');
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
                <td>${(device.data_usage / (1024 * 1024)).toFixed(2)} MB</td>
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

function loadNetworkUsageData() {
    const ctx = document.getElementById('networkUsageChart');
    if (ctx) {
        fetchWithAuth('/api/network_usage')
            .then(response => response.json())
            .then(data => {
                renderNetworkUsageChart(ctx, data);
                updateNetworkUsageStats(data);
            })
            .catch(error => {
                console.error('Error fetching network usage data:', error);
                if (error.message === 'Unauthorized') {
                    window.location.href = '/login';
                }
            });
    }
}

function renderNetworkUsageChart(ctx, data) {
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: [{
                label: 'Network Usage (MB)',
                data: data.values,
                borderColor: 'rgb(75, 192, 192)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                tension: 0.1,
                fill: true
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
            },
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            if (context.parsed.y !== null) {
                                label += context.parsed.y.toFixed(2) + ' MB';
                            }
                            return label;
                        }
                    }
                }
            }
        }
    });
}

function updateNetworkUsageStats(data) {
    const totalUsage = data.values.reduce((a, b) => a + b, 0).toFixed(2);
    const averageUsage = (totalUsage / data.values.length).toFixed(2);
    const maxUsage = Math.max(...data.values).toFixed(2);

    const statsContainer = document.getElementById('networkUsageStats');
    if (statsContainer) {
        statsContainer.innerHTML = `
            <div class="card mb-3">
                <div class="card-body">
                    <h5 class="card-title">Network Usage Statistics</h5>
                    <p class="card-text">Total Usage: ${totalUsage} MB</p>
                    <p class="card-text">Average Hourly Usage: ${averageUsage} MB</p>
                    <p class="card-text">Peak Usage: ${maxUsage} MB</p>
                </div>
            </div>
        `;
    }
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Content Loaded');
    const path = window.location.pathname;
    const isProtectedPage = ['/devices', '/network_usage'].includes(path);

    if (isProtectedPage) {
        if (checkAuthentication()) {
            initializeSocket();
            if (path === '/devices') {
                loadDevices();
            } else if (path === '/network_usage') {
                loadNetworkUsageData();
            }
        }
    }

    const deviceList = document.getElementById('device-list');
    const scanButton = document.getElementById('scan-button');

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

    if (deviceList) {
        deviceList.addEventListener('click', function(event) {
            if (event.target.classList.contains('toggle-device')) {
                const deviceId = event.target.getAttribute('data-device-id');
                toggleDevice(deviceId);
            }
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
