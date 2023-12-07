#import <UIKit/UIKit.h>
#import "utilities/codesign/coretrust_bug.h"
#import "utilities/codesign/codesign.h"
#import "utilities/codesign/choma/FAT.h"
#import "utilities/codesign/choma/FileStream.h"
#import "utilities/codesign/choma/MemoryStream.h"
#import "utilities/codesign/choma/MachO.h"
#import <copyfile.h>
#import "utilities/codesign/choma/Host.h"
#import <sys/mman.h>
#import <Foundation/Foundation.h>
#import <spawn.h>
#import <sys/utsname.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <sys/stat.h>
#import <spawn.h>
#import <mach-o/dyld.h>
#import <TargetConditionals.h>
#import <dlfcn.h>


#import <sys/ttycom.h>
#import <sys/ioctl.h>


@interface ViewController : UIViewController

@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UITextField *textField;
@property (nonatomic, strong) UITextView *logTextView;
@property (nonatomic, strong) UIButton *signButton;
- (void)viewDidLoad;
- (void)logMessage:(NSString *)message;
- (void)signButtonTapped;
@end



#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1

#ifdef __cplusplus
extern "C" {
#endif

extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);
void sign_binary(NSString * binary_path, ViewController * self);

int memory_stream_copy_data(MemoryStream *originStream, uint64_t originOffset, MemoryStream *targetStream, uint64_t targetOffset, size_t size);

int fd_is_valid(int fd);
NSString* getNSStringFromFile(int fd);
BOOL isMachoFile(NSString* filePath);
void fixPermissionsOfAppBundle(NSString* appBundlePath);
int spawnRoot(NSString* path, NSArray* args, NSString** stdOut, NSString** stdErr);

#ifdef __cplusplus
}
#endif



int fd_is_valid(int fd)
{
    return fcntl(fd, F_GETFD) != -1 || errno != EBADF;
}

NSString* getNSStringFromFile(int fd)
{
    NSMutableString* ms = [NSMutableString new];
    ssize_t num_read;
    char c;
    if(!fd_is_valid(fd)) return @"";
    while((num_read = read(fd, &c, sizeof(c))))
    {
        [ms appendString:[NSString stringWithFormat:@"%c", c]];
        if(c == '\n') break;
    }
    return ms.copy;
}

BOOL isMachoFile(NSString* filePath)
{
    FILE* file = fopen(filePath.fileSystemRepresentation, "r");
    if(!file) return NO;

    fseek(file, 0, SEEK_SET);
    uint32_t magic;
    fread(&magic, sizeof(uint32_t), 1, file);
    fclose(file);

    return magic == FAT_MAGIC || magic == FAT_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
}

void fixPermissionsOfAppBundle(NSString* appBundlePath)
{
    // Apply correct permissions (First run, set everything to 644, owner 33)
    NSURL* fileURL;
    NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:appBundlePath] includingPropertiesForKeys:nil options:0 errorHandler:nil];
    while(fileURL = [enumerator nextObject])
    {
        NSString* filePath = fileURL.path;
        chown(filePath.fileSystemRepresentation, 33, 33);
        chmod(filePath.fileSystemRepresentation, 0644);
    }

    // Apply correct permissions (Second run, set executables and directories to 0755)
    enumerator = [[NSFileManager defaultManager] enumeratorAtURL:[NSURL fileURLWithPath:appBundlePath] includingPropertiesForKeys:nil options:0 errorHandler:nil];
    while(fileURL = [enumerator nextObject])
    {
        NSString* filePath = fileURL.path;

        BOOL isDir;
        [[NSFileManager defaultManager] fileExistsAtPath:fileURL.path isDirectory:&isDir];

        if(isDir || isMachoFile(filePath))
        {
            chmod(filePath.fileSystemRepresentation, 0755);
        }
    }
}

int spawnRoot(NSString* path, NSArray* args, NSString** stdOut, NSString** stdErr)
{
    NSMutableArray* argsM = args.mutableCopy ?: [NSMutableArray new];
    [argsM insertObject:path atIndex:0];
    
    NSUInteger argCount = [argsM count];
    char **argsC = (char **)malloc((argCount + 1) * sizeof(char*));

    for (NSUInteger i = 0; i < argCount; i++)
    {
        argsC[i] = strdup([[argsM objectAtIndex:i] UTF8String]);
    }
    argsC[argCount] = NULL;

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    posix_spawnattr_set_persona_np(&attr, 99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
    posix_spawnattr_set_persona_uid_np(&attr, 0);
    posix_spawnattr_set_persona_gid_np(&attr, 0);

    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);

    int outErr[2];
    if(stdErr)
    {
        pipe(outErr);
        posix_spawn_file_actions_adddup2(&action, outErr[1], STDERR_FILENO);
        posix_spawn_file_actions_addclose(&action, outErr[0]);
    }

    int out[2];
    if(stdOut)
    {
        pipe(out);
        posix_spawn_file_actions_adddup2(&action, out[1], STDOUT_FILENO);
        posix_spawn_file_actions_addclose(&action, out[0]);
    }
    
    pid_t task_pid;
    int status = -200;
    int spawnError = posix_spawn(&task_pid, [path UTF8String], &action, &attr, (char* const*)argsC, NULL);
    posix_spawnattr_destroy(&attr);
    for (NSUInteger i = 0; i < argCount; i++)
    {
        free(argsC[i]);
    }
    free(argsC);
    
    if(spawnError != 0)
    {
        NSLog(@"posix_spawn error %d\n", spawnError);
        return spawnError;
    }

    __block volatile BOOL _isRunning = YES;
    NSMutableString* outString = [NSMutableString new];
    NSMutableString* errString = [NSMutableString new];
    dispatch_semaphore_t sema = 0;
    dispatch_queue_t logQueue;
    if(stdOut || stdErr)
    {
        logQueue = dispatch_queue_create("com.opa334.TrollStore.LogCollector", NULL);
        sema = dispatch_semaphore_create(0);

        int outPipe = out[0];
        int outErrPipe = outErr[0];

        __block BOOL outEnabled = (BOOL)stdOut;
        __block BOOL errEnabled = (BOOL)stdErr;
        dispatch_async(logQueue, ^
        {
            while(_isRunning)
            {
                @autoreleasepool
                {
                    if(outEnabled)
                    {
                        [outString appendString:getNSStringFromFile(outPipe)];
                    }
                    if(errEnabled)
                    {
                        [errString appendString:getNSStringFromFile(outErrPipe)];
                    }
                }
            }
            dispatch_semaphore_signal(sema);
        });
    }

    do
    {
        if (waitpid(task_pid, &status, 0) != -1) {
            NSLog(@"Child status %d", WEXITSTATUS(status));
        } else
        {
            perror("waitpid");
            _isRunning = NO;
            return -222;
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    _isRunning = NO;
    if(stdOut || stdErr)
    {
        if(stdOut)
        {
            close(out[1]);
        }
        if(stdErr)
        {
            close(outErr[1]);
        }

        // wait for logging queue to finish
        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

        if(stdOut)
        {
            *stdOut = outString.copy;
        }
        if(stdErr)
        {
            *stdErr = errString.copy;
        }
    }

    return WEXITSTATUS(status);
}

char *extract_preferred_slice(const char *fatPath)
{
    FAT *fat = fat_init_from_path(fatPath);
    if (!fat) return NULL;
    MachO *macho = fat_find_preferred_slice(fat);
    if (!macho) return NULL;
    
    char *temp = strdup("/tmp/XXXXXX");
    int fd = mkstemp(temp);

    MemoryStream *outStream = file_stream_init_from_path(temp, 0, 0, FILE_STREAM_FLAG_WRITABLE | FILE_STREAM_FLAG_AUTO_EXPAND);
    MemoryStream *machoStream = macho_get_stream(macho);
    memory_stream_copy_data(machoStream, 0, outStream, 0, memory_stream_get_size(machoStream));

    fat_free(fat);
    memory_stream_free(outStream);
    close(fd);
    return temp;
}

void sign_binary(NSString * binary_path, ViewController * self) {
    codesign_sign_adhoc([binary_path UTF8String], NO, nil);
    char *machoPath = extract_preferred_slice(binary_path.UTF8String);
    [self logMessage:[NSString stringWithFormat:@"[*] Got slice_path: %s", machoPath]];
    apply_coretrust_bypass(machoPath);
    copyfile(machoPath, [binary_path UTF8String], 0, COPYFILE_ALL | COPYFILE_MOVE | COPYFILE_UNLINK);
    [self logMessage:@"[*] Copying new file to binary_path ..."];
    chmod([binary_path UTF8String], 0755);
    [self logMessage:@"[*] Set permission to 0755"];
}
