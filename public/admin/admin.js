// WIXYEEZ Admin Panel JavaScript

// Check authentication
async function checkAuth() {
    try {
        const response = await fetch('/api/auth/check');
        const data = await response.json();
        
        if (!data.authenticated && !window.location.pathname.includes('login')) {
            window.location.href = '/admin/login';
        }
        
        if (data.authenticated && data.username) {
            const usernameEl = document.getElementById('adminUsername');
            if (usernameEl) usernameEl.textContent = data.username;
        }
    } catch (error) {
        console.error('Auth check failed:', error);
    }
}

// Login handler
if (document.getElementById('loginForm')) {
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorEl = document.getElementById('errorMessage');
        
        try {
            const response = await fetch('/api/login.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (data.success) {
                window.location.href = data.redirect || '/admin/dashboard';
            } else {
                errorEl.textContent = data.error || 'Login failed';
                errorEl.style.display = 'block';
            }
        } catch (error) {
            errorEl.textContent = 'Connection error';
            errorEl.style.display = 'block';
        }
    });
}

// Logout handler
const logoutBtn = document.getElementById('logoutBtn');
if (logoutBtn) {
    logoutBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        
        try {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/admin/login';
        } catch (error) {
            console.error('Logout failed:', error);
        }
    });
}

// Load dashboard stats
async function loadDashboard() {
    try {
        const response = await fetch('/api/stats.php');
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('totalProducts').textContent = data.stats.products;
            document.getElementById('totalOrders').textContent = data.stats.orders;
            document.getElementById('totalRevenue').textContent = data.stats.revenue + '₽';
            document.getElementById('todayOrders').textContent = data.stats.today_orders;
            
            // Category breakdown
            const categoryBreakdown = document.getElementById('categoryBreakdown');
            if (categoryBreakdown && data.stats.categories) {
                categoryBreakdown.innerHTML = data.stats.categories.map(cat => `
                    <div class="category-item">
                        <span class="category-name">
                            ${getCategoryEmoji(cat.category)} ${cat.category}
                        </span>
                        <span class="category-count">${cat.count}</span>
                    </div>
                `).join('');
            }
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Load products
async function loadProducts(category = 'all') {
    const grid = document.getElementById('productsGrid');
    if (!grid) return;
    
    grid.innerHTML = '<p>Loading products...</p>';
    
    try {
        const url = category === 'all' 
            ? '/api/products'
            : `/api/products?category=${encodeURIComponent(category)}`;
            
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.success && data.products.length > 0) {
            grid.innerHTML = data.products.map(product => `
                <div class="product-card">
                    <div class="product-header">
                        <span class="product-category">${product.emoji} ${product.category}</span>
                        <h3 class="product-name">${product.name}</h3>
                        <p class="product-desc">${product.description || ''}</p>
                    </div>
                    <div class="product-body">
                        <div class="product-price">
                            ${product.price}₽
                            ${product.old_price > product.price ? 
                                `<span class="product-old-price">${product.old_price}₽</span>` : ''}
                            ${product.discount > 0 ? 
                                `<span class="product-discount">-${product.discount}%</span>` : ''}
                        </div>
                        <div class="product-actions">
                            <button class="btn-edit" onclick="editProduct(${product.id})">Edit</button>
                            <button class="btn-delete" onclick="deleteProduct(${product.id}, '${product.name}')">Delete</button>
                        </div>
                    </div>
                </div>
            `).join('');
        } else {
            grid.innerHTML = '<p>No products found</p>';
        }
    } catch (error) {
        console.error('Failed to load products:', error);
        grid.innerHTML = '<p>Error loading products</p>';
    }
}

// Filter products
function filterProducts() {
    const category = document.getElementById('categoryFilter').value;
    loadProducts(category);
}

// Search products
let searchTimeout;
function searchProducts() {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
        const query = document.getElementById('searchInput').value.toLowerCase();
        // Implementation needed for search
        console.log('Search:', query);
    }, 300);
}

// Show add product modal
function showAddProductModal() {
    document.getElementById('modalTitle').textContent = 'Add Product';
    document.getElementById('productForm').reset();
    document.getElementById('productId').value = '';
    document.getElementById('productModal').classList.add('active');
}

// Edit product
async function editProduct(id) {
    // Get product data
    const response = await fetch('/api/products');
    const data = await response.json();
    
    const product = data.products.find(p => p.id === id);
    if (product) {
        document.getElementById('modalTitle').textContent = 'Edit Product';
        document.getElementById('productId').value = product.id;
        document.getElementById('productName').value = product.name;
        document.getElementById('productDesc').value = product.description || '';
        document.getElementById('productCategory').value = product.category;
        document.getElementById('productPrice').value = product.price;
        document.getElementById('productOldPrice').value = product.old_price || '';
        document.getElementById('productDiscount').value = product.discount || '';
        document.getElementById('productImage').value = product.image_url || '';
        
        document.getElementById('productModal').classList.add('active');
    }
}

// Delete product
async function deleteProduct(id, name) {
    if (!confirm(`Delete product "${name}"?`)) return;
    
    try {
        const response = await fetch(`/api/delete_product.php?id=${id}`);
        const data = await response.json();
        
        if (data.success) {
            alert('Product deleted successfully!');
            loadProducts();
        } else {
            alert('Failed to delete product');
        }
    } catch (error) {
        console.error('Failed to delete product:', error);
        alert('Error deleting product');
    }
}

// Close modal
function closeModal() {
    document.getElementById('productModal').classList.remove('active');
}

// Product form submission
if (document.getElementById('productForm')) {
    document.getElementById('productForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const productId = document.getElementById('productId').value;
        const productData = {
            name: document.getElementById('productName').value,
            description: document.getElementById('productDesc').value,
            category: document.getElementById('productCategory').value,
            price: parseFloat(document.getElementById('productPrice').value),
            old_price: parseFloat(document.getElementById('productOldPrice').value) || null,
            discount: parseInt(document.getElementById('productDiscount').value) || 0,
            image_url: document.getElementById('productImage').value || null
        };
        
        if (productId) {
            productData.id = parseInt(productId);
        }
        
        try {
            const url = productId 
                ? '/api/update_product.php'
                : '/api/add_product.php';
                
            const response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(productData)
            });
            
            const data = await response.json();
            
            if (data.success) {
                alert(productId ? 'Product updated!' : 'Product added!');
                closeModal();
                loadProducts();
            } else {
                alert('Error: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            console.error('Failed to save product:', error);
            alert('Error saving product');
        }
    });
}

// Refresh stats
async function refreshStats() {
    await loadDashboard();
    alert('Stats refreshed!');
}

// Get category emoji
function getCategoryEmoji(category) {
    const emojis = {
        'Услуги': '🛡️',
        'Сеты': '📦',
        'Сопровождение': '🎯'
    };
    return emojis[category] || '🔥';
}

// Check auth on page load
window.addEventListener('DOMContentLoaded', () => {
    checkAuth();
});
