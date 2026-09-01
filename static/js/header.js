/**
 * static/js/header.js
 *
 * Shared header logic for every dashboard page (dashboard, meter, queue).
 * Loaded via <script src="/static/js/header.js"></script> in base.html.
 *
 * Responsibilities:
 *   - Load current user info into header avatar / name / role
 *   - Load nav badge counts (outages, meter, queue)
 *   - Load active outage dropdown list
 *   - Toggle user dropdown and outage dropdown
 *   - Show / hide logout confirmation overlay
 *   - Expose window.setLiveStatus() for SocketIO connect/disconnect
 *   - Expose window.headerRefreshBadges() for page scripts to call
 */
(function () {
    'use strict';

    /* ── DOM helpers ─────────────────────────────────────────────────────── */
    function $id(id) { return document.getElementById(id); }
    function setText(id, text) { var el = $id(id); if (el) el.textContent = text; }

    function getInitials(name) {
        var parts = (name || '').trim().split(/\s+/);
        if (parts.length >= 2) {
            return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
        }
        return (name || '?').substring(0, 2).toUpperCase();
    }

    function esc(s) {
        return String(s || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function setBadge(id, count) {
        var el = $id(id);
        if (!el) return;
        el.textContent = count;
        el.style.display = count > 0 ? 'block' : 'none';
    }

    function timeAgoShort(iso) {
        var diff = Math.floor((Date.now() - new Date(iso)) / 1000);
        if (diff < 60)   return diff + 's ago';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        return Math.floor(diff / 3600) + 'h ago';
    }

    /* ── Load current user ───────────────────────────────────────────────── */
    async function loadUser() {
        try {
            var res  = await fetch('/api/me', { credentials: 'same-origin' });
            var data = await res.json();
            if (!data.success) return;

            var u          = data.user;
            var name       = u.full_name || u.username || '?';
            var role       = u.role || 'staff';
            var ini        = getInitials(name);

            setText('headerAvatar',   ini);
            setText('headerUsername', name);
            setText('headerRole',     role);
            setText('ddAvatar',       ini);
            setText('ddName',         name);
            setText('ddRole',         role);
            setText('logoutUserName', name);

            /* Show User Management link for admin / superadmin */
            if (role === 'admin' || role === 'superadmin') {
                var mgmt = $id('ddUserMgmt');
                if (mgmt) mgmt.style.display = 'flex';
            }
        } catch (e) {
            /* Silent — header still functional without user info */
        }
    }

    /* ── Load nav badge counts ───────────────────────────────────────────── */
    async function loadBadges() {
        try {
            var res  = await fetch('/api/badge_counts', { credentials: 'same-origin' });
            var data = await res.json();
            if (!data.success) return;

            setBadge('outagesBadge', data.counts.outages);
            setBadge('meterBadge',   data.counts.meter);
            setBadge('queueBadge',   data.counts.queue);
        } catch (e) { /* silent */ }
    }

    /* ── Load outage dropdown ────────────────────────────────────────────── */
    async function loadOutages() {
        try {
            var res  = await fetch('/api/recent_outages', { credentials: 'same-origin' });
            var data = await res.json();
            var list = $id('odList');
            var cnt  = $id('outageWidgetCount');
            if (!list) return;

            if (!data.success || !data.outages || !data.outages.length) {
                list.innerHTML = '<div class="od-empty">✅ No active outages</div>';
                if (cnt) cnt.textContent = '0';
                return;
            }

            if (cnt) cnt.textContent = data.outages.length;

            list.innerHTML = data.outages.map(function (o) {
                var priority = (o.priority || '').toUpperCase();
                var dotClass = priority === 'CRITICAL' ? 'critical'
                             : priority === 'HIGH'     ? 'high'
                             : 'minor';
                var ago = o.first_report_time ? timeAgoShort(o.first_report_time) : '';

                return '<div class="od-item" onclick="window.location.href=\'/dashboard\'">'
                    + '<div class="od-dot ' + dotClass + '"></div>'
                    + '<div class="od-info">'
                    + '<div class="od-loc">'
                    + esc(o.barangay || '')
                    + (o.town ? ', ' + esc(o.town) : '')
                    + '</div>'
                    + '<div class="od-meta">'
                    + '<span class="od-badge ' + esc(o.status) + '">' + esc(o.status) + '</span>'
                    + '<span>' + (o.report_count || 0) + ' report' + (o.report_count !== 1 ? 's' : '') + '</span>'
                    + (o.feeder_name ? '<span>⚡ ' + esc(o.feeder_name) + '</span>' : '')
                    + (ago ? '<span>' + ago + '</span>' : '')
                    + '</div>'
                    + '</div>'
                    + '</div>';
            }).join('');
        } catch (e) { /* silent */ }
    }

    /* ── Dropdown toggles ────────────────────────────────────────────────── */
    window.toggleUserDropdown = function () {
        var dd   = $id('userDropdown');
        var btn  = $id('userBtn');
        var c    = $id('userCaret');
        var outDD= $id('outageDropdown');
        if (!dd) return;

        var isOpen = dd.classList.toggle('open');
        if (btn) btn.classList.toggle('open', isOpen);
        if (c)   c.style.transform = isOpen ? 'rotate(180deg)' : '';

        /* Close other dropdown */
        if (outDD) outDD.classList.remove('open');
    };

    window.toggleOutageDropdown = function () {
        var dd    = $id('outageDropdown');
        var userDD= $id('userDropdown');
        var userBtn=$id('userBtn');
        var c     = $id('userCaret');
        if (!dd) return;

        var isOpen = dd.classList.toggle('open');

        /* Close other dropdown */
        if (userDD)  userDD.classList.remove('open');
        if (userBtn) userBtn.classList.remove('open');
        if (c)       c.style.transform = '';

        /* Refresh outages each time it opens */
        if (isOpen) loadOutages();
    };

    /* ── Logout overlay ──────────────────────────────────────────────────── */
    window.showLogout = function () {
        var o = $id('logoutOverlay');
        if (o) o.classList.add('show');
        var dd = $id('userDropdown');
        if (dd) dd.classList.remove('open');
        var c = $id('userCaret');
        if (c) c.style.transform = '';
    };

    window.hideLogout = function () {
        var o = $id('logoutOverlay');
        if (o) o.classList.remove('show');
    };

    /* ── Live status pill (called by SocketIO event handlers) ────────────── */
    window.setLiveStatus = function (online) {
        var pill  = $id('livePill');
        var label = $id('livePillLabel');
        if (!pill || !label) return;
        pill.className = 'ileco-live-pill' + (online ? '' : ' offline');
        label.textContent = online ? 'Live' : 'Offline';
    };

    /* ── Expose badge refresh so page scripts can trigger it ─────────────── */
    window.headerRefreshBadges = loadBadges;

    /* ── Close dropdowns on outside click ───────────────────────────────── */
    document.addEventListener('click', function (e) {
        var uw = $id('userWidget');
        var ow = document.querySelector('.ileco-outage-widget');

        if (uw && !uw.contains(e.target)) {
            var dd = $id('userDropdown');
            if (dd) dd.classList.remove('open');
            var btn = $id('userBtn');
            if (btn) btn.classList.remove('open');
            var c = $id('userCaret');
            if (c) c.style.transform = '';
        }

        if (ow && !ow.contains(e.target)) {
            var outDD = $id('outageDropdown');
            if (outDD) outDD.classList.remove('open');
        }
    });

    /* ── Keyboard: Escape closes overlays ───────────────────────────────── */
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            window.hideLogout();
            var dd = $id('userDropdown');
            if (dd) dd.classList.remove('open');
            var c = $id('userCaret');
            if (c) c.style.transform = '';
            var outDD = $id('outageDropdown');
            if (outDD) outDD.classList.remove('open');
        }
    });

    /* ── Bootstrap ───────────────────────────────────────────────────────── */
    function init() {
        loadUser();
        loadBadges();

        /* Refresh badges every 2 minutes */
        setInterval(loadBadges, 120000);

        /* Refresh outage widget count every 15 seconds */
        setInterval(function () {
            /* Only refresh the count, not the full dropdown list */
            fetch('/api/badge_counts', { credentials: 'same-origin' })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (!d.success) return;
                    var cnt = $id('outageWidgetCount');
                    if (cnt) cnt.textContent = d.counts.outages;
                    setBadge('outagesBadge', d.counts.outages);
                    setBadge('meterBadge',   d.counts.meter);
                    setBadge('queueBadge',   d.counts.queue);
                })
                .catch(function () {});
        }, 15000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();