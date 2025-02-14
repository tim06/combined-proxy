package combinedproxy

import (
	"context"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

    	mDNS "github.com/miekg/dns"
    	"github.com/sagernet/sing/common"
    	E "github.com/sagernet/sing/common/exceptions"
    	M "github.com/sagernet/sing/common/metadata"
    	"github.com/sagernet/sing/common/observable"
    	"github.com/sagernet/sing/common/varbin"
    	"github.com/sagernet/sing/common/x/list"
    	singbox "github.com/tim06/sing-box/experimental/libbox"
    )

    // ==============================================================================
    // Обёртки для Sing‑box (общие функции)
    // ==============================================================================

    func SetupSingbox(basePath, workingPath, tempPath string, isTVOS bool) {
    	log.Printf("SetupSingbox: basePath=%s, workingPath=%s, tempPath=%s, isTVOS=%v", basePath, workingPath, tempPath, isTVOS)
    	singbox.Setup(basePath, workingPath, tempPath, isTVOS)
    }

    func SingboxRedirectStderr(path string) error {
    	log.Printf("SingboxRedirectStderr: path=%s", path)
    	return singbox.RedirectStderr(path)
    }

    func SingboxSetMemoryLimit(enabled bool) {
    	log.Printf("SingboxSetMemoryLimit: enabled=%v", enabled)
    	singbox.SetMemoryLimit(enabled)
    }

    func SingBoxVersion() string {
    	version := singbox.Version()
    	log.Printf("SingBoxVersion: %s", version)
    	return version
    }

    // ==============================================================================
    // Собственные типы для настроек и сетевых интерфейсов
    // ==============================================================================

    type CombinedTunOptions struct {
    	GetInet4Address             RoutePrefixIterator
    	GetInet6Address             RoutePrefixIterator
    	GetDNSServerAddress         string
    	GetMTU                      int32
    	GetAutoRoute                bool
    	GetStrictRoute              bool
    	GetInet4RouteAddress        RoutePrefixIterator
    	GetInet6RouteAddress        RoutePrefixIterator
    	GetInet4RouteExcludeAddress RoutePrefixIterator
    	GetInet6RouteExcludeAddress RoutePrefixIterator
    	GetInet4RouteRange          RoutePrefixIterator
    	GetInet6RouteRange          RoutePrefixIterator
    	GetIncludePackage           StringIterator
    	GetExcludePackage           StringIterator
    	IsHTTPProxyEnabled          bool
    	GetHTTPProxyServer          string
    	GetHTTPProxyServerPort      int32
    	GetHTTPProxyBypassDomain    StringIterator
    	GetHTTPProxyMatchDomain     StringIterator
    }

    type RoutePrefixIterator interface {
    	Next() *RoutePrefix
    	HasNext() bool
    }

    type RoutePrefix struct {
    	address netip.Addr
    	prefix  int
    }

    func (p *RoutePrefix) Address() string {
    	return p.address.String()
    }

    func (p *RoutePrefix) Prefix() int32 {
    	return int32(p.prefix)
    }

    type StringIterator interface {
    	Len() int32
    	HasNext() bool
    	Next() string
    }

    func convertFromSingboxTunOptions(options singbox.TunOptions) CombinedTunOptions {
    	address, _ := options.GetDNSServerAddress()
    	return CombinedTunOptions{
    		GetInet4Address:             MapRoutePrefixIterator(options.GetInet4Address()),
    		GetInet6Address:             MapRoutePrefixIterator(options.GetInet6Address()),
    		GetDNSServerAddress:         address,
    		GetMTU:                      options.GetMTU(),
    		GetAutoRoute:                options.GetAutoRoute(),
    		GetStrictRoute:              options.GetStrictRoute(),
    		GetInet4RouteAddress:        MapRoutePrefixIterator(options.GetInet4RouteAddress()),
    		GetInet6RouteAddress:        MapRoutePrefixIterator(options.GetInet6RouteAddress()),
    		GetInet4RouteExcludeAddress: MapRoutePrefixIterator(options.GetInet4RouteExcludeAddress()),
    		GetInet6RouteExcludeAddress: MapRoutePrefixIterator(options.GetInet6RouteExcludeAddress()),
    		GetInet4RouteRange:          MapRoutePrefixIterator(options.GetInet4RouteRange()),
    		GetInet6RouteRange:          MapRoutePrefixIterator(options.GetInet6RouteRange()),
    		GetIncludePackage:           options.GetIncludePackage(),
    		GetExcludePackage:           options.GetExcludePackage(),
    		IsHTTPProxyEnabled:          options.IsHTTPProxyEnabled(),
    		GetHTTPProxyServer:          options.GetHTTPProxyServer(),
    		GetHTTPProxyServerPort:      options.GetHTTPProxyServerPort(),
    		GetHTTPProxyBypassDomain:    options.GetHTTPProxyBypassDomain(),
    		GetHTTPProxyMatchDomain:     options.GetHTTPProxyMatchDomain(),
    	}
    }

    func mapRoutePrefix(libPrefix *singbox.RoutePrefix) *RoutePrefix {
    	parsed, err := netip.ParseAddr(libPrefix.Address())
    	if err != nil {
    		log.Printf("mapRoutePrefix: error parsing address %s: %v", libPrefix.Address(), err)
    		return nil
    	}
    	return &RoutePrefix{
    		address: parsed,
    		prefix:  int(libPrefix.Prefix()),
    	}
    }

    func MapRoutePrefixIterator(libIt singbox.RoutePrefixIterator) RoutePrefixIterator {
    	return &routePrefixIteratorAdapter{orig: libIt}
    }

    type routePrefixIteratorAdapter struct {
    	orig singbox.RoutePrefixIterator
    }

    func (a *routePrefixIteratorAdapter) Next() *RoutePrefix {
    	libPrefix := a.orig.Next()
    	result := mapRoutePrefix(libPrefix)
    	log.Printf("routePrefixIteratorAdapter.Next: result=%v", result)
    	return result
    }

    func (a *routePrefixIteratorAdapter) HasNext() bool {
    	return a.orig.HasNext()
    }

    //
    // Определения для WIFIState
    //

    // Наш внешний тип WIFIState
    type WIFIState struct {
    	SSID  string
    	BSSID string
    }

    func mapWIFIState(ext *WIFIState) *singbox.WIFIState {
    	if ext == nil {
    		return nil
    	}
    	return &singbox.WIFIState{
    		SSID:  ext.SSID,
    		BSSID: ext.BSSID,
    	}
    }

    //
    // Определения для сетевого интерфейса
    //

    type CombinedNetworkInterface struct {
    	Index     int32
    	MTU       int32
    	Name      string
    	Addresses StringIterator
    	Flags     int32
    }

    type CombinedNetworkInterfaceIterator interface {
    	Next() *CombinedNetworkInterface
    	HasNext() bool
    }

    type combinedNetworkInterfaceIteratorAdapter struct {
    	it CombinedNetworkInterfaceIterator
    }

    func convertCombinedNetworkInterfaceToSingbox(ni *CombinedNetworkInterface) *singbox.NetworkInterface {
    	if ni == nil {
    		return nil
    	}
    	return &singbox.NetworkInterface{
    		Index:     ni.Index,
    		MTU:       ni.MTU,
    		Name:      ni.Name,
    		Addresses: ni.Addresses,
    		Flags:     ni.Flags,
    	}
    }

    func (a *combinedNetworkInterfaceIteratorAdapter) Next() *singbox.NetworkInterface {
    	ni := a.it.Next()
    	result := convertCombinedNetworkInterfaceToSingbox(ni)
    	log.Printf("combinedNetworkInterfaceIteratorAdapter.Next: result=%v", result)
    	return result
    }

    func (a *combinedNetworkInterfaceIteratorAdapter) HasNext() bool {
    	return a.it.HasNext()
    }

    // ==============================================================================
    // Интерфейсы платформы
    // ==============================================================================

    type CombinedPlatformInterfaceInternal interface {
    	UsePlatformAutoDetectInterfaceControl() bool
    	AutoDetectInterfaceControl(fd int32) error
    	OpenTun(options CombinedTunOptions) (int32, error)
    	WriteLog(message string)
    	UseProcFS() bool
    	FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (int32, error)
    	PackageNameByUid(uid int32) (string, error)
    	UIDByPackageName(packageName string) (int32, error)
    	UsePlatformDefaultInterfaceMonitor() bool
    	StartDefaultInterfaceMonitor(listener CombinedInterfaceUpdateListener) error
    	CloseDefaultInterfaceMonitor(listener CombinedInterfaceUpdateListener) error
    	UsePlatformInterfaceGetter() bool
    	GetInterfaces() (CombinedNetworkInterfaceIterator, error)
    	UnderNetworkExtension() bool
    	IncludeAllNetworks() bool
    	ClearDNSCache()
    	ReadWIFIState() *singbox.WIFIState
    }

    type CombinedPlatformInterfaceExternal interface {
    	UsePlatformAutoDetectInterfaceControl() bool
    	AutoDetectInterfaceControl(fd int32) error
    	OpenTun(
    		inet4RouteAddress RoutePrefixIterator,
    		inet6Address RoutePrefixIterator,
    		DNSServerAddress string,
    		MTU int32,
    		AutoRoute bool,
    		trictRoute bool,
    		Inet4RouteAddress RoutePrefixIterator,
    		Inet6RouteAddress RoutePrefixIterator,
    		Inet4RouteExcludeAddress RoutePrefixIterator,
    		Inet6RouteExcludeAddress RoutePrefixIterator,
    		Inet4RouteRange RoutePrefixIterator,
    		Inet6RouteRange RoutePrefixIterator,
    		IncludePackage StringIterator,
    		ExcludePackage StringIterator,
    		IsHTTPProxyEnabled bool,
    		HTTPProxyServer string,
    		HTTPProxyServerPort int32,
    		HTTPProxyBypassDomain StringIterator,
    		GetHTTPProxyMatchDomain StringIterator,
    	) (int32, error)
    	WriteLog(message string)
    	UseProcFS() bool
    	FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (int32, error)
    	PackageNameByUid(uid int32) (string, error)
    	UIDByPackageName(packageName string) (int32, error)
    	UsePlatformDefaultInterfaceMonitor() bool
    	StartDefaultInterfaceMonitor(listener CombinedInterfaceUpdateListener) error
    	CloseDefaultInterfaceMonitor(listener CombinedInterfaceUpdateListener) error
    	UsePlatformInterfaceGetter() bool
    	GetInterfaces() (CombinedNetworkInterfaceIterator, error)
    	UnderNetworkExtension() bool
    	IncludeAllNetworks() bool
    	ClearDNSCache()
    	ReadWIFIState() *WIFIState
    }

    type CombinedInterfaceUpdateListener interface {
    	UpdateDefaultInterface(interfaceName string, interfaceIndex int32)
    }

    type interfaceUpdateListenerAdapter struct {
    	impl CombinedInterfaceUpdateListener
    }

    func (a *interfaceUpdateListenerAdapter) UpdateDefaultInterface(interfaceName string, interfaceIndex int32) {
    	a.impl.UpdateDefaultInterface(interfaceName, interfaceIndex)
    }

    //
    // Обёртка для преобразования внешнего интерфейса во внутренний
    //

    type platformInterfaceWrapper struct {
    	ext CombinedPlatformInterfaceExternal
    }

    func (w *platformInterfaceWrapper) UsePlatformAutoDetectInterfaceControl() bool {
    	return w.ext.UsePlatformAutoDetectInterfaceControl()
    }
    func (w *platformInterfaceWrapper) AutoDetectInterfaceControl(fd int32) error {
    	return w.ext.AutoDetectInterfaceControl(fd)
    }
    func (w *platformInterfaceWrapper) OpenTun(options CombinedTunOptions) (int32, error) {
    	log.Printf("platformInterfaceWrapper.OpenTun: options=%+v", options)
    	result, err := w.ext.OpenTun(
    		options.GetInet4Address,
    		options.GetInet6Address,
    		options.GetDNSServerAddress,
    		options.GetMTU,
    		options.GetAutoRoute,
    		options.GetStrictRoute,
    		options.GetInet4RouteAddress,
    		options.GetInet6RouteAddress,
    		options.GetInet4RouteExcludeAddress,
    		options.GetInet6RouteExcludeAddress,
    		options.GetInet4RouteRange,
    		options.GetInet6RouteRange,
    		options.GetIncludePackage,
    		options.GetExcludePackage,
    		options.IsHTTPProxyEnabled,
    		options.GetHTTPProxyServer,
    		options.GetHTTPProxyServerPort,
    		options.GetHTTPProxyBypassDomain,
    		options.GetHTTPProxyMatchDomain,
    	)
    	log.Printf("platformInterfaceWrapper.OpenTun: result=%d, err=%v", result, err)
    	return result, err
    }
    func (w *platformInterfaceWrapper) WriteLog(message string) {
    	log.Printf("platformInterfaceWrapper.WriteLog: %s", message)
    	w.ext.WriteLog(message)
    }
    func (w *platformInterfaceWrapper) UseProcFS() bool {
    	return w.ext.UseProcFS()
    }
    func (w *platformInterfaceWrapper) FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (int32, error) {
    	return w.ext.FindConnectionOwner(ipProtocol, sourceAddress, sourcePort, destinationAddress, destinationPort)
    }
    func (w *platformInterfaceWrapper) PackageNameByUid(uid int32) (string, error) {
    	return w.ext.PackageNameByUid(uid)
    }
    func (w *platformInterfaceWrapper) UIDByPackageName(packageName string) (int32, error) {
    	return w.ext.UIDByPackageName(packageName)
    }
    func (w *platformInterfaceWrapper) UsePlatformDefaultInterfaceMonitor() bool {
    	return w.ext.UsePlatformDefaultInterfaceMonitor()
    }
    func (w *platformInterfaceWrapper) StartDefaultInterfaceMonitor(listener CombinedInterfaceUpdateListener) error {
    	return w.ext.StartDefaultInterfaceMonitor(listener)
    }
    func (w *platformInterfaceWrapper) CloseDefaultInterfaceMonitor(listener CombinedInterfaceUpdateListener) error {
    	return w.ext.CloseDefaultInterfaceMonitor(listener)
    }
    func (w *platformInterfaceWrapper) UsePlatformInterfaceGetter() bool {
    	return w.ext.UsePlatformInterfaceGetter()
    }
    func (w *platformInterfaceWrapper) GetInterfaces() (CombinedNetworkInterfaceIterator, error) {
    	return w.ext.GetInterfaces()
    }
    func (w *platformInterfaceWrapper) UnderNetworkExtension() bool {
    	return w.ext.UnderNetworkExtension()
    }
    func (w *platformInterfaceWrapper) IncludeAllNetworks() bool {
    	return w.ext.IncludeAllNetworks()
    }
    func (w *platformInterfaceWrapper) ClearDNSCache() {
    	w.ext.ClearDNSCache()
    }
    func (w *platformInterfaceWrapper) ReadWIFIState() *singbox.WIFIState {
    	extState := w.ext.ReadWIFIState()
    	log.Printf("platformInterfaceWrapper.ReadWIFIState: extState=%+v", extState)
    	return mapWIFIState(extState)
    }

    //
    // Адаптер для singbox.PlatformInterface, реализующий внутренний интерфейс
    //

    type platformInterfaceAdapterInternal struct {
    	impl CombinedPlatformInterfaceInternal
    }

    func (a *platformInterfaceAdapterInternal) UsePlatformAutoDetectInterfaceControl() bool {
    	return a.impl.UsePlatformAutoDetectInterfaceControl()
    }
    func (a *platformInterfaceAdapterInternal) AutoDetectInterfaceControl(fd int32) error {
    	return a.impl.AutoDetectInterfaceControl(fd)
    }
    func (a *platformInterfaceAdapterInternal) OpenTun(options singbox.TunOptions) (int32, error) {
    	ct := convertFromSingboxTunOptions(options)
    	log.Printf("platformInterfaceAdapterInternal.OpenTun: converted options=%+v", ct)
    	result, err := a.impl.OpenTun(ct)
    	log.Printf("platformInterfaceAdapterInternal.OpenTun: result=%d, err=%v", result, err)
    	return result, err
    }
    func (a *platformInterfaceAdapterInternal) WriteLog(message string) {
    	a.impl.WriteLog(message)
    }
    func (a *platformInterfaceAdapterInternal) UseProcFS() bool {
    	return a.impl.UseProcFS()
    }
    func (a *platformInterfaceAdapterInternal) FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (int32, error) {
    	return a.impl.FindConnectionOwner(ipProtocol, sourceAddress, sourcePort, destinationAddress, destinationPort)
    }
    func (a *platformInterfaceAdapterInternal) PackageNameByUid(uid int32) (string, error) {
    	return a.impl.PackageNameByUid(uid)
    }
    func (a *platformInterfaceAdapterInternal) UIDByPackageName(packageName string) (int32, error) {
    	return a.impl.UIDByPackageName(packageName)
    }
    func (a *platformInterfaceAdapterInternal) UsePlatformDefaultInterfaceMonitor() bool {
    	return a.impl.UsePlatformDefaultInterfaceMonitor()
    }
    func (a *platformInterfaceAdapterInternal) StartDefaultInterfaceMonitor(listener singbox.InterfaceUpdateListener) error {
    	adapter := &interfaceUpdateListenerAdapter{impl: listener.(CombinedInterfaceUpdateListener)}
    	return a.impl.StartDefaultInterfaceMonitor(adapter)
    }
    func (a *platformInterfaceAdapterInternal) CloseDefaultInterfaceMonitor(listener singbox.InterfaceUpdateListener) error {
    	adapter := &interfaceUpdateListenerAdapter{impl: listener.(CombinedInterfaceUpdateListener)}
    	return a.impl.CloseDefaultInterfaceMonitor(adapter)
    }
    func (a *platformInterfaceAdapterInternal) UsePlatformInterfaceGetter() bool {
    	return a.impl.UsePlatformInterfaceGetter()
    }
    func (a *platformInterfaceAdapterInternal) GetInterfaces() (singbox.NetworkInterfaceIterator, error) {
    	it, err := a.impl.GetInterfaces()
    	if err != nil {
    		log.Printf("platformInterfaceAdapterInternal.GetInterfaces: err=%v", err)
    		return nil, err
    	}
    	return &combinedNetworkInterfaceIteratorAdapter{it: it}, nil
    }
    func (a *platformInterfaceAdapterInternal) UnderNetworkExtension() bool {
    	return a.impl.UnderNetworkExtension()
    }
    func (a *platformInterfaceAdapterInternal) IncludeAllNetworks() bool {
    	return a.impl.IncludeAllNetworks()
    }
    func (a *platformInterfaceAdapterInternal) ClearDNSCache() {
    	a.impl.ClearDNSCache()
    }
    func (a *platformInterfaceAdapterInternal) ReadWIFIState() *singbox.WIFIState {
    	return a.impl.ReadWIFIState()
    }

    //
    // Обёртки для BoxService (Sing‑box)
    //

    type CombinedBoxService interface {
    	Start() error
    	Stop() error
    	Close() error
    	NeedWIFIState() bool
    }

    type boxServiceAdapter struct {
    	bs *singbox.BoxService
    }

    func (a *boxServiceAdapter) Start() error {
    	log.Printf("boxServiceAdapter.Start called")
    	return a.bs.Start()
    }
    func (a *boxServiceAdapter) Stop() error {
    	log.Printf("boxServiceAdapter.Stop called")
    	return a.bs.Close()
    }
    func (a *boxServiceAdapter) Close() error {
    	log.Printf("boxServiceAdapter.Close called")
    	return a.bs.Close()
    }
    func (a *boxServiceAdapter) NeedWIFIState() bool {
    	return a.bs.NeedWIFIState()
    }

    // NewService — экспортированная функция, которая оборачивает внешний интерфейс,
    // добавляет логирование и создаёт BoxService.
    func NewService(configContent string, platformInterface CombinedPlatformInterfaceExternal) (CombinedBoxService, error) {
    	log.Printf("NewService: configContent=%s", configContent)
    	log.Printf("NewService: initializing platform interface wrapper")
    	wrapped := &platformInterfaceWrapper{ext: platformInterface}
    	log.Printf("NewService: creating internal adapter")
    	adapter := &platformInterfaceAdapterInternal{impl: wrapped}

    	log.Printf("NewService: calling singbox.NewService")
    	bs, err := singbox.NewService(configContent, adapter)
    	if err != nil {
    		log.Printf("NewService: error from singbox.NewService: %v", err)
    		return nil, err
    	}
    	log.Printf("NewService: successfully created BoxService: %v", bs)
    	return &boxServiceAdapter{bs: bs}, nil
    }

    //
    // Обёртки для локального DNS‑транспорта
    //

    type CombinedExchangeContext struct {
    	context   context.Context
    	message   mDNS.Msg
    	addresses []netip.Addr
    	error     error

    	Inner *singbox.ExchangeContext
    }

    type exchangeContextAdapter struct {
    	impl CombinedExchangeContext
    }

    type CombinedLocalDNSTransport interface {
    	Raw() bool
    	Lookup(ctx *CombinedExchangeContext, network string, domain string) error
    	Exchange(ctx *CombinedExchangeContext, message []byte) error
    }

    type localDNSTransportAdapter struct {
    	impl CombinedLocalDNSTransport
    }

    func (a *localDNSTransportAdapter) Raw() bool {
    	return a.impl.Raw()
    }

    func (a *localDNSTransportAdapter) Lookup(ctx *singbox.ExchangeContext, network string, domain string) error {
    	return a.impl.Lookup(&CombinedExchangeContext{Inner: ctx}, network, domain)
    }

    func (a *localDNSTransportAdapter) Exchange(ctx *singbox.ExchangeContext, message []byte) error {
    	return a.impl.Exchange(&CombinedExchangeContext{Inner: ctx}, message)
    }

    func RegisterLocalDNSTransport(transport CombinedLocalDNSTransport) {
    	adapter := &localDNSTransportAdapter{impl: transport}
    	singbox.RegisterLocalDNSTransport(adapter)
    }

    //
    // Дополнительные функции для CombinedExchangeContext
    //

    type Func interface {
    	Invoke() error
    }

    func (c *CombinedExchangeContext) OnCancel(callback Func) {
    	go func() {
    		<-c.context.Done()
    		callback.Invoke()
    	}()
    }

    func (c *CombinedExchangeContext) Success(result string) {
    	c.addresses = common.Map(common.Filter(strings.Split(result, "\n"), func(it string) bool {
    		return !common.IsEmpty(it)
    	}), func(it string) netip.Addr {
    		return M.ParseSocksaddrHostPort(it, 0).Unwrap().Addr
    	})
    }

    func (c *CombinedExchangeContext) RawSuccess(result []byte) {
    	err := c.message.Unpack(result)
    	if err != nil {
    		c.error = E.Cause(err, "parse response")
    	}
    }

    func (c *CombinedExchangeContext) ErrnoCode(code int32) {
    	c.error = syscall.Errno(code)
    }

    //
    // Дополнительные типы для командного сервера и соединений
    //

    type CombinedCommandServerHandler interface {
    	ServiceReload() error
    	PostServiceClose()
    	GetSystemProxyStatus() *CombinedSystemProxyStatus
    	SetSystemProxyEnabled(isEnabled bool) error
    }

    type CombinedSystemProxyStatus struct {
    	Available bool
    	Enabled   bool
    }

    type CombinedCommandServer struct {
    	listener net.Listener
    	handler  CombinedCommandServerHandler

    	access     sync.Mutex
    	savedLines list.List[string]
    	maxLines   int
    	subscriber *observable.Subscriber[string]
    	observer   *observable.Observer[string]
    	service    *CombinedBoxService

    	// Каналы для одного клиента
    	urlTestUpdate chan struct{}
    	modeUpdate    chan struct{}
    	logReset      chan struct{}
    	events        chan myEvent

    	closedConnections []CombinedConnection
    }

    type myEvent interface {
    	writeTo(writer varbin.Writer)
    }

    type CombinedConnection struct {
    	ID            string
    	Inbound       string
    	InboundType   string
    	IPVersion     int32
    	Network       string
    	Source        string
    	Destination   string
    	Domain        string
    	Protocol      string
    	User          string
    	FromOutbound  string
    	CreatedAt     int64
    	ClosedAt      int64
    	Uplink        int64
    	Downlink      int64
    	UplinkTotal   int64
    	DownlinkTotal int64
    	Rule          string
    	Outbound      string
    	OutboundType  string
    	ChainList     []string
    }