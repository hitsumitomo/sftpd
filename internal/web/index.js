const { createApp, ref, defineAsyncComponent, watch } = Vue;

const basePath = window.location.pathname.replace(/\/$/, '');

/**
 * Loads a template HTML file from the server.
 * @param {string} name - Template name without extension.
 * @returns {Promise<string>} Promise that resolves to template HTML content.
 */
function loadTemplate(name) {
    return fetch(`${basePath}/tpl/${name}.html`).then(r => r.text());
}

/**
 * Performs a GET API request with JSON response.
 * Redirects to login if unauthorized.
 * @param {string} url - API endpoint path.
 * @param {object} [opts={}] - Additional fetch options.
 * @returns {Promise<object>} Promise that resolves to JSON response.
 * @throws {Error} When API request fails or is unauthorized.
 */
function apiGet(url, opts = {}) {
    return fetch(`${basePath}/${url}`, {
        method: 'GET',
        credentials: 'include',
        ...opts,
    }).then(async r => {
        if (!r.ok) {
            if (r.status === 401 || r.status === 403) {
                window.location.href = basePath || '/';
                throw new Error('Redirecting...');
            }
            const text = await r.text();
            const err = new Error(text || r.statusText);
            err.status = r.status;
            throw err;
        }
        return r.json();
    });
}

/**
 * Performs a POST API request with JSON data.
 * Redirects to login if unauthorized.
 * @param {string} url - API endpoint path.
 * @param {object} data - Data to send as JSON.
 * @param {object} [opts={}] - Additional fetch options.
 * @returns {Promise<string>} Promise that resolves to response text.
 * @throws {Error} When API request fails or is unauthorized.
 */
function apiPost(url, data, opts = {}) {
    const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
    return fetch(`${basePath}/${url}`, {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify(data),
        ...opts
    }).then(async r => {
        if (!r.ok) {
            if (r.status === 401 || r.status === 403) {
                window.location.href = basePath || '/';
                throw new Error('Redirecting...');
            }
            const text = await r.text();
            const err = new Error(text || r.statusText);
            err.status = r.status;
            throw err;
        }
        return r.text();
    });
}

/**
 * Async Vue component for editing config.
 * @component
 * @prop {object} config - The configuration object to edit.
 * @emits save - Emitted after successful save.
 */
const ConfigEditor = defineAsyncComponent(async () => {
    const template = await loadTemplate('config-editor');
    return {
        props: ['config'],
        emits: ['save'],
        setup(props, { emit }) {
            const localConfig = ref(JSON.parse(JSON.stringify(props.config)));
            const error = ref('');
            const success = ref('');
            function save() {
                error.value = '';
                success.value = '';
                apiPost('config', localConfig.value)
                    .then(() => {
                        success.value = 'Config updated!';
                        emit('save');
                    })
                    .catch(e => {
                        error.value = 'Failed to update config: ' + (e.message || e);
                    });
            }
            return { localConfig, save, error, success };
        },
        computed: {
            localConfigText: {
                get() { return JSON.stringify(this.localConfig, null, 4); },
                set(val) {
                    try { this.localConfig = JSON.parse(val); } catch {}
                }
            }
        },
        template
    };
});

/**
 * Async Vue component for login form.
 * @component
 */
const LoginForm = defineAsyncComponent(async () => {
    const template = await loadTemplate('login');
    return {
        setup() {
            const username = ref('');
            const password = ref('');
            const error = ref('');
            const loading = ref(false);
            async function login() {
                error.value = '';
                loading.value = true;
                try {
                    const res = await fetch(`${basePath}/login`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username: username.value, password: password.value }),
                        credentials: 'include'
                    });
                    if (!res.ok) throw new Error(await res.text());
                    window.location.reload();
                } catch (e) {
                    error.value = 'Invalid username or password';
                }
                loading.value = false;
            }
            return { username, password, error, loading, login };
        },
        template
    };
});

/**
 * Main Vue application component.
 * Handles config loading, editing, saving, and UI state.
 * @component
 */
const App = defineAsyncComponent(async () => {
    const template = await loadTemplate('app');
    return {
        setup() {
            const config = ref(null);
            const draftConfig = ref(null);
            const loading = ref(true);
            const error = ref('');
            const editing = ref(false);
            const section = ref('users');
            const saving = ref(false);
            const saveError = ref('');
            const saveSuccess = ref(false);
            const showLogin = ref(false);
            const groupForms = ref({});
            const addMenuOpen = ref(false);

            /**
             * Loads the configuration from the server and prepares group forms.
             * Sets up default filters and mapping lists for groups.
             * Handles authentication errors and updates loading/error state.
             * @returns {Promise<void>}
             */
            async function loadConfig() {
                loading.value = true;
                error.value = '';
                try {
                    const res = await apiGet('config');
                    config.value = res;
                    draftConfig.value = JSON.parse(JSON.stringify(res));
                    if (!draftConfig.value.http.filter)
                        draftConfig.value.http.filter = { whitelist: "", blacklist: "" };
                    groupForms.value = {};
                    if (draftConfig.value.groups) {
                        for (const [name, group] of Object.entries(draftConfig.value.groups)) {
                            if (!group.filter) group.filter = { whitelist: "", blacklist: "" };
                            if (!('whitelist' in group.filter)) group.filter.whitelist = "";
                            if (!('blacklist' in group.filter)) group.filter.blacklist = "";
                            let mappingList = [];
                            if (group.mapping && typeof group.mapping === 'object') {
                                for (const [mname, m] of Object.entries(group.mapping)) {
                                    mappingList.push({
                                        name: mname,
                                        path: m.path || '',
                                        mode: m.mode || 'rw'
                                    });
                                }
                            }
                            groupForms.value[name] = {
                                name,
                                mappingList,
                                mappingError: ''
                            };
                        }
                    }
                    loading.value = false;
                } catch (e) {
                    if (e.status === 401) {
                        showLogin.value = true;
                    } else if (e.message !== 'Redirecting...') {
                        error.value = 'Failed to load config: ' + (e.message || e);
                    }
                    loading.value = false;
                }
            }

            /**
             * Prepares the users form by initializing mapping lists, filters, and max_sessions.
             * Ensures all user objects have the required properties for editing.
             */
            function prepareUsersForm() {
                if (!draftConfig.value.users) return;
                for (const [login, user] of Object.entries(draftConfig.value.users)) {
                    user.login = login;
                    if (!user.filter) user.filter = { whitelist: "", blacklist: "" };
                    user.mappingList = [];
                    if (typeof user.max_sessions !== 'number') user.max_sessions = 0;
                    if (user.mapping && typeof user.mapping === 'object') {
                        for (const [name, m] of Object.entries(user.mapping)) {
                            user.mappingList.push({
                                name,
                                path: m.path || '',
                                mode: m.mode || 'rw'
                            });
                        }
                    }
                    user.mappingError = '';
                }
            }

            /**
             * Applies edits from the users form to the draftConfig.
             * Converts mapping lists to mapping objects and ensures max_sessions is set.
             */
            function applyUsersEdit() {
                if (!draftConfig.value.users) return;
                for (const user of Object.values(draftConfig.value.users)) {
                    if (!user.filter) user.filter = { whitelist: "", blacklist: "" };
                    if (!user.filter.hasOwnProperty('whitelist')) user.filter.whitelist = "";
                    if (!user.filter.hasOwnProperty('blacklist')) user.filter.blacklist = "";
                    const mappingObj = {};
                    for (const m of user.mappingList) {
                        if (!m.name || !m.path || !m.mode) continue;
                        mappingObj[m.name] = { path: m.path, mode: m.mode };
                    }
                    user.mapping = mappingObj;
                    user.mappingError = '';
                    if (typeof user.max_sessions !== 'number') user.max_sessions = 0;
                }
            }

            /**
             * Applies edits from the group forms to the draftConfig.
             * Converts mapping lists to mapping objects for each group.
             * @param {string} [name] - Optional group name to update a single group.
             */
            function applyGroupEdit(name) {
                const groupsToUpdate = name ? [name] : Object.keys(groupForms.value);
                for (const groupName of groupsToUpdate) {
                    if (!groupForms.value[groupName] || !draftConfig.value.groups[groupName]) continue;
                    const groupForm = groupForms.value[groupName];
                    const group = draftConfig.value.groups[groupName];
                    if (!group.filter) group.filter = { whitelist: "", blacklist: "" };
                    if (!('whitelist' in group.filter)) group.filter.whitelist = "";
                    if (!('blacklist' in group.filter)) group.filter.blacklist = "";
                    const mappingObj = {};
                    for (const m of groupForm.mappingList) {
                        if (!m.name || !m.path || !m.mode) continue;
                        mappingObj[m.name] = { path: m.path, mode: m.mode };
                    }
                    group.mapping = mappingObj;
                    groupForm.mappingError = '';
                }
            }

            /**
             * Adds a new empty mapping entry to the specified user's mapping list.
             * @param {object} user - The user object to add a mapping to.
             */
            function addMapping(user) {
                user.mappingList.push({ name: '', path: '', mode: 'rw' });
            }

            /**
             * Removes a mapping entry from the specified user's mapping list.
             * @param {object} user - The user object.
             * @param {number} idx - Index of the mapping to remove.
             */
            function removeMapping(user, idx) {
                user.mappingList.splice(idx, 1);
            }

            /**
             * Adds a new empty mapping entry to the specified group's mapping list.
             * @param {string} name - The group name.
             */
            function addGroupMapping(name) {
                groupForms.value[name].mappingList.push({ name: '', path: '', mode: 'rw' });
            }

            /**
             * Removes a mapping entry from the specified group's mapping list.
             * @param {string} name - The group name.
             * @param {number} idx - Index of the mapping to remove.
             */
            function removeGroupMapping(name, idx) {
                groupForms.value[name].mappingList.splice(idx, 1);
            }

            /**
             * Resets save success and error state before saving config.
             */
            function applyDraft() {
                saveSuccess.value = false;
                saveError.value = '';
            }

            /**
             * Saves the current draft configuration to the server.
             * Applies user and group edits, cleans up temporary fields, and handles errors.
             * @returns {Promise<void>}
             */
            async function saveConfig() {
                saving.value = true;
                saveError.value = '';
                saveSuccess.value = false;
                applyDraft();
                applyUsersEdit();
                applyGroupEdit();
                const configToSend = JSON.parse(JSON.stringify(draftConfig.value));
                if (configToSend.users) {
                    for (const user of Object.values(configToSend.users)) {
                        delete user.mappingList;
                        delete user.mappingError;
                        if (typeof user.max_sessions !== 'number') user.max_sessions = 0;
                    }
                }
                try {
                    await apiPost('config', configToSend);
                    saveSuccess.value = true;
                    setTimeout(() => { saveSuccess.value = false; }, 800);
                    if (draftConfig.value.users) {
                        for (const user of Object.values(draftConfig.value.users)) {
                            if (user.password) user.password = '';
                            if (user.pubkey) user.pubkey = '';
                            if (!user.filter) user.filter = { whitelist: "", blacklist: "" };
                        }
                    }
                    if (draftConfig.value.groups) {
                        for (const group of Object.values(draftConfig.value.groups)) {
                            if (!group.filter) group.filter = { whitelist: "", blacklist: "" };
                            if (!('whitelist' in group.filter)) group.filter.whitelist = "";
                            if (!('blacklist' in group.filter)) group.filter.blacklist = "";
                        }
                    }
                    if (draftConfig.value.http && draftConfig.value.http.password) {
                        draftConfig.value.http._originalPassword = draftConfig.value.http.password;
                        draftConfig.value.http.password = '';
                    } else if (draftConfig.value.http && draftConfig.value.http._originalPassword) {
                        configToSend.http.password = draftConfig.value.http._originalPassword;
                    }
                    config.value = JSON.parse(JSON.stringify(draftConfig.value));
                } catch (e) {
                    if (e.message !== 'Redirecting...') {
                        saveError.value = e.message || e;
                        setTimeout(() => { saveError.value = ''; }, 800);
                    }
                }
                saving.value = false;
            }

            /**
             * Logs out the current user and redirects to the login page.
             * @returns {Promise<void>}
             */
            async function exit() {
                await fetch(`${basePath}/logout`, {
                    method: 'POST',
                    credentials: 'include',
                });
                window.location.href = basePath || '/';
            }

            /**
             * Adds a new user with default values to the draftConfig.
             * Ensures unique login name.
             */
            const addUser = function() {
                let newUserLogin = "new_user";
                let counter = 1;
                while (draftConfig.value.users && draftConfig.value.users[newUserLogin]) {
                    newUserLogin = `new_user_${counter++}`;
                }
                if (!draftConfig.value.users) draftConfig.value.users = {};
                const newUser = {
                    login: newUserLogin,
                    password: "",
                    groups: "",
                    filter: { whitelist: '', blacklist: '' },
                    mapping: {},
                    mappingList: [],
                    max_sessions: 0
                };
                addMapping(newUser);
                const newUsers = { [newUserLogin]: newUser, ...draftConfig.value.users };
                draftConfig.value.users = newUsers;
                section.value = "users";
            };

            /**
             * Adds a new group with default values to the draftConfig.
             * Ensures unique group name.
             */
            const addGroup = function() {
                let newGroupName = "new_group";
                let counter = 1;
                while (draftConfig.value.groups && draftConfig.value.groups[newGroupName]) {
                    newGroupName = `new_group_${counter++}`;
                }
                if (!draftConfig.value.groups) draftConfig.value.groups = {};
                const newGroup = {
                    filter: { whitelist: '', blacklist: '' },
                    mapping: {}
                };
                const newGroups = { [newGroupName]: newGroup, ...draftConfig.value.groups };
                draftConfig.value.groups = newGroups;
                groupForms.value[newGroupName] = {
                    name: newGroupName,
                    mappingList: [],
                    mappingError: ''
                };
                addGroupMapping(newGroupName);
                section.value = "groups";
            };

            /**
             * Deletes a group from the draftConfig and removes it from all users' group lists.
             * @param {string} name - The group name to delete.
             */
            function delGroup(name) {
                delete draftConfig.value.groups[name];
                for (const u of Object.values(draftConfig.value.users || {})) {
                    if (u.groups) u.groups = u.groups.filter ? u.groups.filter(g => g !== name) : u.groups;
                }
            }

            /**
             * Switches to config editor mode.
             */
            function editConfig() { editing.value = true; }

            /**
             * Callback after saving config in editor mode; reloads config and exits editor.
             */
            function onSave() { editing.value = false; loadConfig(); }

            watch(section, (val) => { if (val === 'users') prepareUsersForm(); });
            watch(draftConfig, () => { if (section.value === 'users') prepareUsersForm(); });

            loadConfig();

            return {
                config, draftConfig, loading, error, editing, editConfig, onSave,
                section, saving, saveError, saveSuccess, showLogin, exit,
                applyDraft, saveConfig, groupForms, applyGroupEdit,
                applyUsersEdit, addMapping, removeMapping, addGroupMapping, removeGroupMapping,
                addUser, addGroup, delGroup, addMenuOpen
            };
        },
        components: { ConfigEditor, LoginForm },
        template
    };
});

createApp({
    components: { App, LoginForm },
    setup() {
        const showLogin = ref(false);
        return { showLogin };
    },
    template: `<login-form v-if="showLogin"></login-form><app v-else></app>`
}).mount('#app');
