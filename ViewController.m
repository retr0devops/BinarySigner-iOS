#import "ViewController.h"

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // Создаем надпись (Label)
    self.titleLabel = [[UILabel alloc] initWithFrame:CGRectMake(20, 100, 200, 30)];
    self.titleLabel.text = @"Binary:";
    [self.titleLabel sizeToFit];
    self.titleLabel.center = CGPointMake(self.view.center.x, self.titleLabel.center.y);
    [self.view addSubview:self.titleLabel];
    
    self.textField = [[UITextField alloc] initWithFrame:CGRectMake(20, 150, 200, 30)];
    self.textField.borderStyle = UITextBorderStyleRoundedRect;
    self.textField.center = CGPointMake(self.view.center.x, self.textField.center.y);
    [self.view addSubview:self.textField];
    
    self.logTextView = [[UITextView alloc] initWithFrame:CGRectMake(20, 200, 300, 150)];
    self.logTextView.layer.borderWidth = 1.0;
    self.logTextView.layer.borderColor = [UIColor lightGrayColor].CGColor;
    self.logTextView.editable = NO;
    self.logTextView.center = CGPointMake(self.view.center.x, self.logTextView.center.y);
    [self.view addSubview:self.logTextView];
    
    self.signButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.signButton setTitle:@"Sign" forState:UIControlStateNormal];
    [self.signButton addTarget:self action:@selector(signButtonTapped) forControlEvents:UIControlEventTouchUpInside];
    self.signButton.frame = CGRectMake(0, 0, 100, 30);
    self.signButton.center = CGPointMake(self.view.center.x, CGRectGetMaxY(self.logTextView.frame) + 30);
    [self.view addSubview:self.signButton];
    
    [self logMessage:@"[*] Program was started."];
}

- (void)logMessage:(NSString *)message {
    NSString *currentLogs = self.logTextView.text;
    NSString *newLogs = [NSString stringWithFormat:@"%@\n%@", currentLogs, message];
    self.logTextView.text = newLogs;
}

- (void)signButtonTapped {
    NSString *plistString = @"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">"
                            "<plist version=\"1.0\">"
                            "<dict>"
                            " <key>application-identifier</key>"
                            " <string>45Y8355FM6.com.retr0dev.test.hack-test</string>"
                            " <key>com.apple.developer.team-identifier</key>"
                            " <string>45Y8355FM6</string>"
                            " <key>get-task-allow</key>"
                            " <true/>"
                            " <key>com.apple.private.security.no-sandbox</key>"
                            " <true/>"
                            " <key>platform-application</key>"
                            " <true/>"
                            " <key>com.apple.private.security.storage.AppDataContainers</key>"
                            " <true/>"
                            " <key>com.apple.private.persona-mgmt</key>"
                            " <true/>"
                            " <key>com.apple.private.security.storage.AppBundles</key>"
                            " <true/>"
                            " <key>com.apple.private.security.storage.MobileDocuments</key>"
                            " <true/>"
                            "</dict>"
                            "</plist>";

    NSString * binary_path = [self.textField text];
    NSData *plistData = [plistString dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *plistDictionary = [NSPropertyListSerialization propertyListWithData:plistData options:NSPropertyListImmutable format:NULL error:nil];
    
    // Checks
    
    [self logMessage:@"[*] Binary was fakesigned with ldid."];
    [self logMessage:@"[*] Now using CoreTrust exploit ..."];
    
    codesign_sign_adhoc([binary_path UTF8String], NO, plistDictionary);
    
    [self logMessage:@"[*] Binary was signed with AdHoc."];
    [self logMessage:@"[*] Applying CoreTrust bypass ..."];

    sign_binary(binary_path, self);
    
    [self logMessage:@"[*] Binary was successfully signed."];
    [self logMessage:@"[*] Done."];
    
}

@end
