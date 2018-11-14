#import "FlutterRsaPlugin.h"
#import <flutter_rsa/flutter_rsa-Swift.h>

@implementation FlutterRsaPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftFlutterRsaPlugin registerWithRegistrar:registrar];
}
@end
