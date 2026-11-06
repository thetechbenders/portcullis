package hostownership

import (
 "slices"
 "testing"
)
func b(x bool)*bool{return &x}
func good()(Plan,Observation){
 id:=Identity{Name:"usb0",Parent:"/sys/devices/usb/1-2",CurrentMAC:"02:11:22:33:44:55",PermanentMAC:"02:11:22:33:44:55",Driver:"r8152",VendorID:"0bda",ProductID:"8156"}
 p:=Plan{Guest:id,Uplink:"eth0",Management:"wlan0"}
 o:=Observation{Guest:&id,Down:b(true),IPv6Disabled:b(true),AcceptRAZero:b(true),
 Carrier:b(false),HasAddresses:b(false),HasRoutes:b(false),Enslaved:b(false),
 NetworkManagerMayActivate:b(false),OtherManagerMayActivate:b(false),
 ManagementPreserved:b(true),ManagementRoutePreserved:b(true),
 IsolatedPeer:b(true),GuardAttested:b(true),UnknownIngressDenied:b(true),
 GuestInputDenied:b(true),GuestOutputDenied:b(true),BypassAttested:b(true),
 KernelCompatible:b(true),RecoveryVerified:b(true),
 BootID:"test-boot",PlanDigest:"test-plan",GuardDigest:"test-guard",NetdevGeneration:"test-netdev"}
 o.Approval=&Approval{Valid:true,BootID:o.BootID,PlanDigest:o.PlanDigest,GuardDigest:o.GuardDigest,NetdevGeneration:o.NetdevGeneration}
 return p,o
}
func TestAllEvidenceRequired(t *testing.T){
 p,o:=good()
 if got:=Evaluate(p,o);!got.MayRequestGuestUp||len(got.Reasons)!=0{t.Fatal(got)}
 if got:=Evaluate(p,Observation{});got.MayRequestGuestUp||len(got.Reasons)==0{t.Fatal(got)}
}
func TestEveryFaultFailsClosed(t *testing.T){
 tests:=map[string]func(*Plan,*Observation){
 "already up":func(_ *Plan,o *Observation){o.Down=b(false)},
 "unknown link":func(_ *Plan,o *Observation){o.Down=nil},
 "guest ipv6":func(_ *Plan,o *Observation){o.IPv6Disabled=b(false)},
 "ra enabled":func(_ *Plan,o *Observation){o.AcceptRAZero=b(false)},
 "new netdev ipv6 reset":func(_ *Plan,o *Observation){o.IPv6Disabled=nil},
 "cable plugged":func(_ *Plan,o *Observation){o.Carrier=b(true)},
 "unknown cable":func(_ *Plan,o *Observation){o.Carrier=nil},
 "address":func(_ *Plan,o *Observation){o.HasAddresses=b(true)},
 "route":func(_ *Plan,o *Observation){o.HasRoutes=b(true)},
 "master":func(_ *Plan,o *Observation){o.Enslaved=b(true)},
 "nm matcher miss":func(_ *Plan,o *Observation){o.NetworkManagerMayActivate=b(true)},
 "nm ownership unknown":func(_ *Plan,o *Observation){o.NetworkManagerMayActivate=nil},
 "other manager":func(_ *Plan,o *Observation){o.OtherManagerMayActivate=b(true)},
 "wlan0 bounced":func(_ *Plan,o *Observation){o.ManagementPreserved=b(false)},
 "return route":func(_ *Plan,o *Observation){o.ManagementRoutePreserved=b(false)},
 "peer unknown":func(_ *Plan,o *Observation){o.IsolatedPeer=nil},
 "guard flushed":func(_ *Plan,o *Observation){o.GuardAttested=b(false)},
 "iifname rename hole":func(_ *Plan,o *Observation){o.UnknownIngressDenied=b(false)},
 "host input":func(_ *Plan,o *Observation){o.GuestInputDenied=b(false)},
 "host output":func(_ *Plan,o *Observation){o.GuestOutputDenied=b(false)},
 "tc xdp unknown":func(_ *Plan,o *Observation){o.BypassAttested=nil},
 "kernel mismatch":func(_ *Plan,o *Observation){o.KernelCompatible=b(false)},
 "no console recovery":func(_ *Plan,o *Observation){o.RecoveryVerified=b(false)},
 "usb replug":func(_ *Plan,o *Observation){o.NetdevGeneration="new-instance"},
 "reboot":func(_ *Plan,o *Observation){o.BootID="new-boot"},
 "new guard":func(_ *Plan,o *Observation){o.GuardDigest="new-guard"},
 "new plan":func(_ *Plan,o *Observation){o.PlanDigest="new-plan"},
 "expired permission":func(_ *Plan,o *Observation){o.Approval.Valid=false},
 "no approval":func(_ *Plan,o *Observation){o.Approval=nil},
 "renamed interface":func(_ *Plan,o *Observation){o.Guest.Name="enx-renamed"},
 "usb port changed":func(_ *Plan,o *Observation){o.Guest.Parent="/sys/devices/usb/1-3"},
 "rebound driver":func(_ *Plan,o *Observation){o.Guest.Driver="cdc_ncm"},
 "permanent mac changed":func(_ *Plan,o *Observation){o.Guest.PermanentMAC="02:11:22:33:44:66"},
 "permanent mac missing":func(_ *Plan,o *Observation){o.Guest.PermanentMAC=""},
 "current mac changed":func(_ *Plan,o *Observation){o.Guest.CurrentMAC="02:11:22:33:44:66"},
 "usb vendor changed":func(_ *Plan,o *Observation){o.Guest.VendorID="ffff"},
 "role collision":func(p *Plan,_ *Observation){p.Uplink=p.Management},
 }
 for name,mutate:=range tests {
  t.Run(name,func(t *testing.T){
   p,o:=good();mutate(&p,&o)
   got:=Evaluate(p,o)
   if got.MayRequestGuestUp||len(got.Reasons)==0{t.Fatalf("unsafe eligibility: %#v",got)}
   if !slices.IsSorted(got.Reasons){t.Fatalf("unstable reason order: %#v",got)}
  })
 }
}
func TestCrashEvidenceNeverClaimsIsolationWithoutReadback(t *testing.T){
 for _,down:=range []bool{true,false}{
  e:=OnFault(false,down)
  if e.GuardAttested||e.AdminDownConfirmed!=down||e.IsolationUnconfirmed==down||!e.ExistingKernelGrantsMayRemain{t.Fatal(e)}
 }
}
