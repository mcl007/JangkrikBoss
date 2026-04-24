// NetAutomation — Frontend JavaScript

document.addEventListener('DOMContentLoaded', () => {
    // ── Sidebar Toggle ──
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    const toggle = document.getElementById('sidebar-toggle');

    if (toggle && sidebar) {
        toggle.addEventListener('click', () => {
            sidebar.classList.toggle('show');
            if (overlay) overlay.classList.toggle('show');
        });
    }
    if (overlay) {
        overlay.addEventListener('click', () => {
            sidebar.classList.remove('show');
            overlay.classList.remove('show');
        });
    }

    // ── Auto-dismiss flash alerts ──
    document.querySelectorAll('.flash-container .alert').forEach(alert => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 6000);
    });

    // ── Form loading states ──
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            // Skip delete forms (inline forms with confirm dialog)
            if (this.classList.contains('d-inline')) return;
            // Skip modal forms (edit device/user modals)
            if (this.closest('.modal')) return;

            const btn = this.querySelector('button[type="submit"]');
            if (btn && !btn.classList.contains('diag-btn')) {
                const originalHtml = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
                btn.disabled = true;
                setTimeout(() => {
                    btn.innerHTML = originalHtml;
                    btn.disabled = false;
                }, 30000);
            }
        });
    });

    // ── Stat card counter animation ──
    document.querySelectorAll('.stat-info h3').forEach(el => {
        const target = parseInt(el.textContent);
        if (isNaN(target) || target === 0) return;
        el.textContent = '0';
        let current = 0;
        const step = Math.max(1, Math.ceil(target / 30));
        const interval = setInterval(() => {
            current += step;
            if (current >= target) {
                current = target;
                clearInterval(interval);
            }
            el.textContent = current;
        }, 30);
    });
});
