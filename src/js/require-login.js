(function (wp) {
    var registerPlugin = wp.plugins.registerPlugin;
    var PluginPostStatusInfo = wp.editPost.PluginPostStatusInfo;
    var el = wp.element.createElement;
    var CheckboxControl = wp.components.CheckboxControl;
    var withSelect = wp.data.withSelect;
    var withDispatch = wp.data.withDispatch;
    var compose = wp.compose.compose;

    var mapSelectToProps = function (select) {
        return {
            requiresLogin: select('core/editor').getEditedPostAttribute('meta')['gtocas_requires_login']
        }
    };

    var mapDispatchToProps = function (dispatch) {
        return {
            setRequiresLogin: function (value) {
                dispatch('core/editor').editPost(
                    {meta: {gtocas_requires_login: value}}
                );
            }
        }
    };

    var RequiresLoginCheckbox = compose(
        withSelect(mapSelectToProps),
        withDispatch(mapDispatchToProps)
    )(function (props) {
        return (
            el(CheckboxControl, {
                label: 'Requires Login',
                checked: props.requiresLogin,
                onChange: function (value) {
                    props.setRequiresLogin(value)
                }
            })
        )
    });

    function RequiresLogin() {
        return (
            el(PluginPostStatusInfo, {}, el(RequiresLoginCheckbox))
        )
    }

    registerPlugin('gtocas-requires-login', {
        render: RequiresLogin
    });
})(window.wp);
