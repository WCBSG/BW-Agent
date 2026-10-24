/* webview2_min.h —— WebView2 里"我们真正用到的那几个接口"。
 *
 * 为什么不全量引入 WebView2.h(2.9MB、上百个接口):
 *   编译慢、看不出用了什么;而这些接口绝大多数我们不碰。
 *   但**方法顺序绝对不能手抄** —— 抄错一个虚表位就是崩溃,所以下面这些
 *   接口体是从官方 SDK(1.0.4258.31)的 WebView2.h 里整块搬来的。
 *
 * 运行时不需要链接任何库:WebView2Loader.dll 作为资源编进 exe,
 * 启动时释放到数据目录再 LoadLibrary + GetProcAddress(见 webview.cpp)。
 * 因此"交付一个 exe"仍然成立;只是这台机器要装 WebView2 运行时
 * (Win10/11 随 Edge 自带,极少数精简系统需要单独装一次)。
 */
#ifndef AGENT_WEBVIEW2_MIN_H
#define AGENT_WEBVIEW2_MIN_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <objbase.h>

/* 官方头里由 midl 生成,这里给一个同义的定义 */
#ifndef MIDL_INTERFACE
#define MIDL_INTERFACE(x) struct __declspec(uuid(x)) __declspec(novtable)
#endif

typedef struct EventRegistrationToken { LONGLONG value; } EventRegistrationToken;

/* 下面这些只在方法签名里出现(指针),前置声明就够 */
struct ICoreWebView2Environment;
struct ICoreWebView2CreateCoreWebView2ControllerCompletedHandler;
struct ICoreWebView2WebResourceResponse;
struct ICoreWebView2NewBrowserVersionAvailableEventHandler;
struct ICoreWebView2Controller;
struct ICoreWebView2ZoomFactorChangedEventHandler;
struct ICoreWebView2MoveFocusRequestedEventHandler;
struct ICoreWebView2FocusChangedEventHandler;
struct ICoreWebView2AcceleratorKeyPressedEventHandler;
struct ICoreWebView2;
struct ICoreWebView2Settings;
struct ICoreWebView2NavigationStartingEventHandler;
struct ICoreWebView2ContentLoadingEventHandler;
struct ICoreWebView2SourceChangedEventHandler;
struct ICoreWebView2HistoryChangedEventHandler;
struct ICoreWebView2NavigationCompletedEventHandler;
struct ICoreWebView2ScriptDialogOpeningEventHandler;
struct ICoreWebView2PermissionRequestedEventHandler;
struct ICoreWebView2ProcessFailedEventHandler;
struct ICoreWebView2AddScriptToExecuteOnDocumentCreatedCompletedHandler;
struct ICoreWebView2ExecuteScriptCompletedHandler;
struct ICoreWebView2CapturePreviewCompletedHandler;
struct ICoreWebView2WebMessageReceivedEventHandler;
struct ICoreWebView2CallDevToolsProtocolMethodCompletedHandler;
struct ICoreWebView2DevToolsProtocolEventReceiver;
struct ICoreWebView2NewWindowRequestedEventHandler;
struct ICoreWebView2DocumentTitleChangedEventHandler;
struct ICoreWebView2ContainsFullScreenElementChangedEventHandler;
struct ICoreWebView2WebResourceRequestedEventHandler;
struct ICoreWebView2WindowCloseRequestedEventHandler;
struct ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler;
struct ICoreWebView2NewWindowRequestedEventArgs;
struct ICoreWebView2Deferral;
struct ICoreWebView2WindowFeatures;
struct ICoreWebView2EnvironmentOptions;

typedef /* [v1_enum] */ 
enum COREWEBVIEW2_MOVE_FOCUS_REASON
    {
        COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC	= 0,
        COREWEBVIEW2_MOVE_FOCUS_REASON_NEXT	= ( COREWEBVIEW2_MOVE_FOCUS_REASON_PROGRAMMATIC + 1 ) ,
        COREWEBVIEW2_MOVE_FOCUS_REASON_PREVIOUS	= ( COREWEBVIEW2_MOVE_FOCUS_REASON_NEXT + 1 ) 
    } 	COREWEBVIEW2_MOVE_FOCUS_REASON;

typedef /* [v1_enum] */ 
enum COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT
    {
        COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG	= 0,
        COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_JPEG	= ( COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG + 1 ) 
    } 	COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT;

typedef /* [v1_enum] */ 
enum COREWEBVIEW2_WEB_RESOURCE_CONTEXT
    {
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL	= 0,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_STYLESHEET	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_DOCUMENT + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_IMAGE	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_STYLESHEET + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_MEDIA	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_IMAGE + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_FONT	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_MEDIA + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_SCRIPT	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_FONT + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_XML_HTTP_REQUEST	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_SCRIPT + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_FETCH	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_XML_HTTP_REQUEST + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_TEXT_TRACK	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_FETCH + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_EVENT_SOURCE	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_TEXT_TRACK + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_WEBSOCKET	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_EVENT_SOURCE + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_MANIFEST	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_WEBSOCKET + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_SIGNED_EXCHANGE	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_MANIFEST + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_PING	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_SIGNED_EXCHANGE + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_CSP_VIOLATION_REPORT	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_PING + 1 ) ,
        COREWEBVIEW2_WEB_RESOURCE_CONTEXT_OTHER	= ( COREWEBVIEW2_WEB_RESOURCE_CONTEXT_CSP_VIOLATION_REPORT + 1 ) 
    } 	COREWEBVIEW2_WEB_RESOURCE_CONTEXT;

MIDL_INTERFACE("b96d755e-0319-4e92-a296-23436f46a1fc")
    ICoreWebView2Environment : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE CreateCoreWebView2Controller( 
            HWND parentWindow,
            ICoreWebView2CreateCoreWebView2ControllerCompletedHandler *handler) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CreateWebResourceResponse( 
            /* [in] */ IStream *content,
            /* [in] */ int statusCode,
            /* [in] */ LPCWSTR reasonPhrase,
            /* [in] */ LPCWSTR headers,
            /* [retval][out] */ ICoreWebView2WebResourceResponse **response) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_BrowserVersionString( 
            /* [retval][out] */ LPWSTR *versionInfo) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_NewBrowserVersionAvailable( 
            /* [in] */ ICoreWebView2NewBrowserVersionAvailableEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_NewBrowserVersionAvailable( 
            /* [in] */ EventRegistrationToken token) = 0;
        
    };

MIDL_INTERFACE("4d00c0d1-9434-4eb6-8078-8697a560334f")
    ICoreWebView2Controller : public IUnknown
    {
    public:
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_IsVisible( 
            /* [retval][out] */ BOOL *isVisible) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_IsVisible( 
            /* [in] */ BOOL isVisible) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_Bounds( 
            /* [retval][out] */ RECT *bounds) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_Bounds( 
            /* [in] */ RECT bounds) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_ZoomFactor( 
            /* [retval][out] */ double *zoomFactor) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_ZoomFactor( 
            /* [in] */ double zoomFactor) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_ZoomFactorChanged( 
            /* [in] */ ICoreWebView2ZoomFactorChangedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_ZoomFactorChanged( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetBoundsAndZoomFactor( 
            /* [in] */ RECT bounds,
            /* [in] */ double zoomFactor) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE MoveFocus( 
            /* [in] */ COREWEBVIEW2_MOVE_FOCUS_REASON reason) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_MoveFocusRequested( 
            /* [in] */ ICoreWebView2MoveFocusRequestedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_MoveFocusRequested( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_GotFocus( 
            /* [in] */ ICoreWebView2FocusChangedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_GotFocus( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_LostFocus( 
            /* [in] */ ICoreWebView2FocusChangedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_LostFocus( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_AcceleratorKeyPressed( 
            /* [in] */ ICoreWebView2AcceleratorKeyPressedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_AcceleratorKeyPressed( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_ParentWindow( 
            /* [retval][out] */ HWND *parentWindow) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_ParentWindow( 
            /* [in] */ HWND parentWindow) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE NotifyParentWindowPositionChanged( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Close( void) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_CoreWebView2( 
            /* [retval][out] */ ICoreWebView2 **coreWebView2) = 0;
        
    };

MIDL_INTERFACE("e562e4f0-d7fa-43ac-8d71-c05150499f00")
    ICoreWebView2Settings : public IUnknown
    {
    public:
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_IsScriptEnabled( 
            /* [retval][out] */ BOOL *isScriptEnabled) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_IsScriptEnabled( 
            /* [in] */ BOOL isScriptEnabled) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_IsWebMessageEnabled( 
            /* [retval][out] */ BOOL *isWebMessageEnabled) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_IsWebMessageEnabled( 
            /* [in] */ BOOL isWebMessageEnabled) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_AreDefaultScriptDialogsEnabled( 
            /* [retval][out] */ BOOL *areDefaultScriptDialogsEnabled) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_AreDefaultScriptDialogsEnabled( 
            /* [in] */ BOOL areDefaultScriptDialogsEnabled) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_IsStatusBarEnabled( 
            /* [retval][out] */ BOOL *isStatusBarEnabled) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_IsStatusBarEnabled( 
            /* [in] */ BOOL isStatusBarEnabled) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_AreDevToolsEnabled( 
            /* [retval][out] */ BOOL *areDevToolsEnabled) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_AreDevToolsEnabled( 
            /* [in] */ BOOL areDevToolsEnabled) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_AreDefaultContextMenusEnabled( 
            /* [retval][out] */ BOOL *enabled) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_AreDefaultContextMenusEnabled( 
            /* [in] */ BOOL enabled) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_AreHostObjectsAllowed( 
            /* [retval][out] */ BOOL *allowed) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_AreHostObjectsAllowed( 
            /* [in] */ BOOL allowed) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_IsZoomControlEnabled( 
            /* [retval][out] */ BOOL *enabled) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_IsZoomControlEnabled( 
            /* [in] */ BOOL enabled) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_IsBuiltInErrorPageEnabled( 
            /* [retval][out] */ BOOL *enabled) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_IsBuiltInErrorPageEnabled( 
            /* [in] */ BOOL enabled) = 0;
        
    };

MIDL_INTERFACE("76eceacb-0462-4d94-ac83-423a6793775e")
    ICoreWebView2 : public IUnknown
    {
    public:
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_Settings( 
            /* [retval][out] */ ICoreWebView2Settings **settings) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_Source( 
            /* [retval][out] */ LPWSTR *uri) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Navigate( 
            /* [in] */ LPCWSTR uri) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE NavigateToString( 
            /* [in] */ LPCWSTR htmlContent) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_NavigationStarting( 
            /* [in] */ ICoreWebView2NavigationStartingEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_NavigationStarting( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_ContentLoading( 
            /* [in] */ ICoreWebView2ContentLoadingEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_ContentLoading( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_SourceChanged( 
            /* [in] */ ICoreWebView2SourceChangedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_SourceChanged( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_HistoryChanged( 
            /* [in] */ ICoreWebView2HistoryChangedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_HistoryChanged( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_NavigationCompleted( 
            /* [in] */ ICoreWebView2NavigationCompletedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_NavigationCompleted( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_FrameNavigationStarting( 
            /* [in] */ ICoreWebView2NavigationStartingEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_FrameNavigationStarting( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_FrameNavigationCompleted( 
            /* [in] */ ICoreWebView2NavigationCompletedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_FrameNavigationCompleted( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_ScriptDialogOpening( 
            /* [in] */ ICoreWebView2ScriptDialogOpeningEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_ScriptDialogOpening( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_PermissionRequested( 
            /* [in] */ ICoreWebView2PermissionRequestedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_PermissionRequested( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_ProcessFailed( 
            /* [in] */ ICoreWebView2ProcessFailedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_ProcessFailed( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE AddScriptToExecuteOnDocumentCreated( 
            /* [in] */ LPCWSTR javaScript,
            /* [in] */ ICoreWebView2AddScriptToExecuteOnDocumentCreatedCompletedHandler *handler) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RemoveScriptToExecuteOnDocumentCreated( 
            /* [in] */ LPCWSTR id) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE ExecuteScript( 
            /* [in] */ LPCWSTR javaScript,
            /* [in] */ ICoreWebView2ExecuteScriptCompletedHandler *handler) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CapturePreview( 
            /* [in] */ COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT imageFormat,
            /* [in] */ IStream *imageStream,
            /* [in] */ ICoreWebView2CapturePreviewCompletedHandler *handler) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Reload( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE PostWebMessageAsJson( 
            /* [in] */ LPCWSTR webMessageAsJson) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE PostWebMessageAsString( 
            /* [in] */ LPCWSTR webMessageAsString) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_WebMessageReceived( 
            /* [in] */ ICoreWebView2WebMessageReceivedEventHandler *handler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_WebMessageReceived( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE CallDevToolsProtocolMethod( 
            /* [in] */ LPCWSTR methodName,
            /* [in] */ LPCWSTR parametersAsJson,
            /* [in] */ ICoreWebView2CallDevToolsProtocolMethodCompletedHandler *handler) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_BrowserProcessId( 
            /* [retval][out] */ UINT32 *value) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_CanGoBack( 
            /* [retval][out] */ BOOL *canGoBack) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_CanGoForward( 
            /* [retval][out] */ BOOL *canGoForward) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GoBack( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GoForward( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetDevToolsProtocolEventReceiver( 
            /* [in] */ LPCWSTR eventName,
            /* [retval][out] */ ICoreWebView2DevToolsProtocolEventReceiver **receiver) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE Stop( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_NewWindowRequested( 
            /* [in] */ ICoreWebView2NewWindowRequestedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_NewWindowRequested( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_DocumentTitleChanged( 
            /* [in] */ ICoreWebView2DocumentTitleChangedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_DocumentTitleChanged( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_DocumentTitle( 
            /* [retval][out] */ LPWSTR *title) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE AddHostObjectToScript( 
            /* [in] */ LPCWSTR name,
            /* [in] */ VARIANT *object) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RemoveHostObjectFromScript( 
            /* [in] */ LPCWSTR name) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE OpenDevToolsWindow( void) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_ContainsFullScreenElementChanged( 
            /* [in] */ ICoreWebView2ContainsFullScreenElementChangedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_ContainsFullScreenElementChanged( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_ContainsFullScreenElement( 
            /* [retval][out] */ BOOL *containsFullScreenElement) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_WebResourceRequested( 
            /* [in] */ ICoreWebView2WebResourceRequestedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_WebResourceRequested( 
            /* [in] */ EventRegistrationToken token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE AddWebResourceRequestedFilter( 
            /* [in] */ const LPCWSTR uri,
            /* [in] */ const COREWEBVIEW2_WEB_RESOURCE_CONTEXT resourceContext) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE RemoveWebResourceRequestedFilter( 
            /* [in] */ const LPCWSTR uri,
            /* [in] */ const COREWEBVIEW2_WEB_RESOURCE_CONTEXT resourceContext) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE add_WindowCloseRequested( 
            /* [in] */ ICoreWebView2WindowCloseRequestedEventHandler *eventHandler,
            /* [out] */ EventRegistrationToken *token) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE remove_WindowCloseRequested( 
            /* [in] */ EventRegistrationToken token) = 0;
        
    };

MIDL_INTERFACE("4e8a3389-c9d8-4bd2-b6b5-124fee6cc14d")
    ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Invoke( 
            /* [in] */ HRESULT errorCode,
            /* [in] */ ICoreWebView2Environment *result) = 0;
        
    };

MIDL_INTERFACE("6c4819f3-c9b7-4260-8127-c9f5bde7f68c")
    ICoreWebView2CreateCoreWebView2ControllerCompletedHandler : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Invoke( 
            /* [in] */ HRESULT errorCode,
            /* [in] */ ICoreWebView2Controller *result) = 0;
        
    };

MIDL_INTERFACE("34acb11c-fc37-4418-9132-f9c21d1eafb9")
    ICoreWebView2NewWindowRequestedEventArgs : public IUnknown
    {
    public:
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_Uri( 
            /* [retval][out] */ LPWSTR *uri) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_NewWindow( 
            /* [in] */ ICoreWebView2 *newWindow) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_NewWindow( 
            /* [retval][out] */ ICoreWebView2 **newWindow) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_Handled( 
            /* [in] */ BOOL handled) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_Handled( 
            /* [retval][out] */ BOOL *handled) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_IsUserInitiated( 
            /* [retval][out] */ BOOL *isUserInitiated) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetDeferral( 
            /* [retval][out] */ ICoreWebView2Deferral **deferral) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_WindowFeatures( 
            /* [retval][out] */ ICoreWebView2WindowFeatures **value) = 0;
        
    };

MIDL_INTERFACE("d4c185fe-c81c-4989-97af-2d3fa7ab5651")
    ICoreWebView2NewWindowRequestedEventHandler : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE Invoke( 
            /* [in] */ ICoreWebView2 *sender,
            /* [in] */ ICoreWebView2NewWindowRequestedEventArgs *args) = 0;
        
    };

MIDL_INTERFACE("2fde08a8-1e9a-4766-8c05-95a9ceb9d1c5")
    ICoreWebView2EnvironmentOptions : public IUnknown
    {
    public:
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_AdditionalBrowserArguments( 
            /* [retval][out] */ LPWSTR *value) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_AdditionalBrowserArguments( 
            /* [in] */ LPCWSTR value) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_Language( 
            /* [retval][out] */ LPWSTR *value) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_Language( 
            /* [in] */ LPCWSTR value) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_TargetCompatibleBrowserVersion( 
            /* [retval][out] */ LPWSTR *value) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_TargetCompatibleBrowserVersion( 
            /* [in] */ LPCWSTR value) = 0;
        
        virtual /* [propget] */ HRESULT STDMETHODCALLTYPE get_AllowSingleSignOnUsingOSPrimaryAccount( 
            /* [retval][out] */ BOOL *allow) = 0;
        
        virtual /* [propput] */ HRESULT STDMETHODCALLTYPE put_AllowSingleSignOnUsingOSPrimaryAccount( 
            /* [in] */ BOOL allow) = 0;
        
    };

#endif /* AGENT_WEBVIEW2_MIN_H */
