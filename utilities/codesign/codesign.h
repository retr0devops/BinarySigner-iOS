#import <stdbool.h>
#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

int codesign_sign_adhoc(const char *path, bool preserveMetadata, NSDictionary *customEntitlements);

#ifdef __cplusplus
}
#endif
