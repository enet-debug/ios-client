#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <sqlite3.h>
#import <dlfcn.h>
#import <sys/utsname.h>

static NSString *const LGService = @"online.enet-dev.client-control";
static NSString *const LGIOSIDAccount = @"ios-id";
static NSString *const LGTokenAccount = @"installation-token";

@interface LGControl : NSObject
@property(nonatomic,strong) UIViewController *gate;
@property(nonatomic,strong) NSTimer *timer;
@property(nonatomic,copy) NSString *api;
@property(nonatomic,copy) NSString *project;
@property(nonatomic,copy) NSString *registrationKey;
@property(nonatomic,copy) NSString *telegramUserId;
@property(nonatomic,copy) NSString *telegramName;
@property(nonatomic,copy) NSString *telegramUsername;
+ (instancetype)shared;
- (void)start;
- (void)heartbeat;
@end

static NSString *LGKeychainRead(NSString *account) {
  NSDictionary *q=@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService:LGService,(__bridge id)kSecAttrAccount:account,
    (__bridge id)kSecReturnData:@YES,(__bridge id)kSecMatchLimit:(__bridge id)kSecMatchLimitOne};
  CFTypeRef result=NULL;
  if(SecItemCopyMatching((__bridge CFDictionaryRef)q,&result)!=errSecSuccess)return nil;
  return [[NSString alloc]initWithData:(__bridge_transfer NSData *)result encoding:NSUTF8StringEncoding];
}

static void LGKeychainWrite(NSString *account, NSString *value) {
  NSDictionary *key=@{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService:LGService,(__bridge id)kSecAttrAccount:account};
  SecItemDelete((__bridge CFDictionaryRef)key);
  NSMutableDictionary *item=[key mutableCopy];item[(__bridge id)kSecValueData]=[value dataUsingEncoding:NSUTF8StringEncoding];
  item[(__bridge id)kSecAttrAccessible]=(__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
  SecItemAdd((__bridge CFDictionaryRef)item,NULL);
}

static NSString *LGDeviceModel(void){struct utsname s;uname(&s);return [NSString stringWithUTF8String:s.machine];}
static UIWindow *LGWindow(void){for(UIScene *s in UIApplication.sharedApplication.connectedScenes)if(s.activationState==UISceneActivationStateForegroundActive&&[s isKindOfClass:UIWindowScene.class])for(UIWindow *w in ((UIWindowScene*)s).windows)if(w.isKeyWindow)return w;return nil;}

typedef struct {
  int (*open_v2)(const char *,sqlite3 **,int,const char *);
  int (*close)(sqlite3 *);
  int (*prepare_v2)(sqlite3 *,const char *,int,sqlite3_stmt **,const char **);
  int (*step)(sqlite3_stmt *);
  int (*finalize)(sqlite3_stmt *);
  const void *(*column_blob)(sqlite3_stmt *,int);
  int (*column_bytes)(sqlite3_stmt *,int);
  int (*bind_int64)(sqlite3_stmt *,int,sqlite3_int64);
} LGSQLiteAPI;

static LGSQLiteAPI *LGSQLite(void) {
  static LGSQLiteAPI api;static BOOL ready;static dispatch_once_t once;
  dispatch_once(&once,^{
    void *handle=dlopen("/usr/lib/libsqlite3.dylib",RTLD_LAZY|RTLD_LOCAL);if(!handle)return;
    api.open_v2=dlsym(handle,"sqlite3_open_v2");api.close=dlsym(handle,"sqlite3_close");
    api.prepare_v2=dlsym(handle,"sqlite3_prepare_v2");api.step=dlsym(handle,"sqlite3_step");api.finalize=dlsym(handle,"sqlite3_finalize");
    api.column_blob=dlsym(handle,"sqlite3_column_blob");api.column_bytes=dlsym(handle,"sqlite3_column_bytes");api.bind_int64=dlsym(handle,"sqlite3_bind_int64");
    ready=api.open_v2&&api.close&&api.prepare_v2&&api.step&&api.finalize&&api.column_blob&&api.column_bytes&&api.bind_int64;
  });
  return ready?&api:NULL;
}

static NSString *LGAccountsDatabasePath(void) {
  NSMutableArray<NSURL *> *roots=[NSMutableArray arrayWithObject:[NSURL fileURLWithPath:NSHomeDirectory() isDirectory:YES]];
  NSURL *group=[NSFileManager.defaultManager containerURLForSecurityApplicationGroupIdentifier:@"group.ph.telegra.Telegraph"];
  if(group)[roots addObject:group];
  for(NSURL *root in roots){
    NSDirectoryEnumerator *items=[NSFileManager.defaultManager enumeratorAtURL:root includingPropertiesForKeys:@[NSURLIsRegularFileKey] options:NSDirectoryEnumerationSkipsHiddenFiles errorHandler:nil];
    for(NSURL *url in items){
      if([url.lastPathComponent isEqualToString:@"db_sqlite"]&&[url.path containsString:@"accounts-metadata"])return url.path;
    }
  }
  return nil;
}

static NSString *LGCurrentTelegramPeerId(void) {
  NSString *path=LGAccountsDatabasePath();if(!path)return nil;
  LGSQLiteAPI *sql=LGSQLite();if(!sql)return nil;
  sqlite3 *db=NULL;if(sql->open_v2(path.UTF8String,&db,SQLITE_OPEN_READONLY|SQLITE_OPEN_NOMUTEX,NULL)!=SQLITE_OK){if(db)sql->close(db);return nil;}
  sqlite3_stmt *statement=NULL;int64_t recordId=0;
  if(sql->prepare_v2(db,"SELECT value FROM t0 WHERE key=0",-1,&statement,NULL)==SQLITE_OK&&sql->step(statement)==SQLITE_ROW){const void *bytes=sql->column_blob(statement,0);int length=sql->column_bytes(statement,0);if(bytes&&length>=8)memcpy(&recordId,bytes,8);}sql->finalize(statement);
  if(!recordId){sql->close(db);return nil;}
  const unsigned char marker[]={6,'p','e','e','r','I','d',1};int64_t peerId=0;
  if(sql->prepare_v2(db,"SELECT value FROM t1 WHERE key=?",-1,&statement,NULL)==SQLITE_OK){sql->bind_int64(statement,1,recordId);if(sql->step(statement)==SQLITE_ROW){const unsigned char *bytes=sql->column_blob(statement,0);int length=sql->column_bytes(statement,0);for(int i=0;bytes&&i+16<=length;i++){if(memcmp(bytes+i,marker,sizeof(marker))==0){memcpy(&peerId,bytes+i+sizeof(marker),8);break;}}}}sql->finalize(statement);sql->close(db);
  return peerId?[NSString stringWithFormat:@"%lld",peerId]:nil;
}

@implementation LGControl
+(instancetype)shared{static LGControl *v;static dispatch_once_t once;dispatch_once(&once,^{v=[self new];});return v;}
-(void)start{
  self.api=@"https://enet-dev.online";self.project=@"LORDGRAM";
  self.registrationKey=@LG_REGISTRATION_KEY;
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1*NSEC_PER_SEC)),dispatch_get_main_queue(),^{[self connect];});
  [[NSNotificationCenter defaultCenter]addObserver:self selector:@selector(heartbeat) name:UIApplicationDidBecomeActiveNotification object:nil];
}
-(void)connect{
  NSString *iosId=LGKeychainRead(LGIOSIDAccount);if(!iosId){iosId=NSUUID.UUID.UUIDString;LGKeychainWrite(LGIOSIDAccount,iosId);}
  if(LGKeychainRead(LGTokenAccount)){[self beginHeartbeat];return;}
  NSDictionary *body=@{@"project":self.project,@"iosId":iosId,@"deviceModel":LGDeviceModel(),@"iosVersion":UIDevice.currentDevice.systemVersion,@"appVersion":[NSBundle mainBundle].infoDictionary[@"CFBundleShortVersionString"]?:@""};
  [self request:@"/api/client/register" body:body registration:YES completion:^(NSDictionary *r){if(r[@"token"])LGKeychainWrite(LGTokenAccount,r[@"token"]);[self apply:r];[self beginHeartbeat];}];
}
-(void)beginHeartbeat{[self heartbeat];[self.timer invalidate];self.timer=[NSTimer scheduledTimerWithTimeInterval:30 target:self selector:@selector(heartbeat) userInfo:nil repeats:YES];}
-(void)heartbeat{
  NSString *t=LGKeychainRead(LGTokenAccount);if(!t)return;
  if(!self.telegramUserId)self.telegramUserId=LGCurrentTelegramPeerId();
  NSMutableDictionary *b=[@{@"appVersion":[NSBundle mainBundle].infoDictionary[@"CFBundleShortVersionString"]?:@""} mutableCopy];
  if(self.telegramUserId)b[@"telegramUserId"]=self.telegramUserId;if(self.telegramName)b[@"telegramName"]=self.telegramName;if(self.telegramUsername)b[@"telegramUsername"]=self.telegramUsername;
  [self request:@"/api/client/heartbeat" body:b registration:NO completion:^(NSDictionary *r){[self apply:r];}];
}
-(void)request:(NSString*)endpoint body:(NSDictionary*)body registration:(BOOL)registration completion:(void(^)(NSDictionary*))completion{
  NSURL *url=[NSURL URLWithString:[self.api stringByAppendingString:endpoint]];if(!url)return;
  NSMutableURLRequest *r=[NSMutableURLRequest requestWithURL:url];r.HTTPMethod=@"POST";[r setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
  [r setValue:registration?self.registrationKey:[NSString stringWithFormat:@"Bearer %@",LGKeychainRead(LGTokenAccount)?:@""] forHTTPHeaderField:registration?@"X-Registration-Key":@"Authorization"];
  r.HTTPBody=[NSJSONSerialization dataWithJSONObject:body options:0 error:nil];r.timeoutInterval=12;
  [[NSURLSession.sharedSession dataTaskWithRequest:r completionHandler:^(NSData*d,NSURLResponse*x,NSError*e){if(e||!d)return;NSDictionary*j=[NSJSONSerialization JSONObjectWithData:d options:0 error:nil];if([j isKindOfClass:NSDictionary.class])dispatch_async(dispatch_get_main_queue(),^{completion(j);});}]resume];
}
-(void)apply:(NSDictionary*)r{NSString *s=r[@"state"];if([s isEqual:@"active"]){[self.gate dismissViewControllerAnimated:NO completion:nil];self.gate=nil;return;}if(![s isEqual:@"blocked"]&&![s isEqual:@"project_disabled"])return;[self show:r[@"message"]?:([s isEqual:@"blocked"]?@"Доступ заблокирован":@"Клиент недоступен")];}
-(void)show:(NSString*)message{
  if(self.gate){((UILabel*)[self.gate.view viewWithTag:91]).text=message;return;}
  UIViewController *v=[UIViewController new];v.modalPresentationStyle=UIModalPresentationFullScreen;v.view.backgroundColor=[UIColor colorWithRed:.035 green:.063 blue:.11 alpha:1];
  UILabel *mark=[UILabel new];mark.text=@"LORDGRAM  /  ACCESS";mark.textColor=[UIColor colorWithRed:.18 green:.73 blue:.83 alpha:1];mark.font=[UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
  UILabel *label=[UILabel new];label.tag=91;label.text=message;label.textColor=UIColor.whiteColor;label.font=[UIFont systemFontOfSize:32 weight:UIFontWeightBold];label.numberOfLines=0;
  UILabel *hint=[UILabel new];hint.text=@"Статус обновится автоматически";hint.textColor=[UIColor colorWithWhite:.65 alpha:1];hint.font=[UIFont systemFontOfSize:14];
  UIStackView *stack=[[UIStackView alloc]initWithArrangedSubviews:@[mark,label,hint]];stack.axis=UILayoutConstraintAxisVertical;stack.spacing=18;stack.translatesAutoresizingMaskIntoConstraints=NO;[v.view addSubview:stack];
  [NSLayoutConstraint activateConstraints:@[[stack.leadingAnchor constraintEqualToAnchor:v.view.leadingAnchor constant:32],[stack.trailingAnchor constraintEqualToAnchor:v.view.trailingAnchor constant:-32],[stack.centerYAnchor constraintEqualToAnchor:v.view.centerYAnchor]]];
  self.gate=v;UIViewController *root=LGWindow().rootViewController;while(root.presentedViewController)root=root.presentedViewController;[root presentViewController:v animated:NO completion:nil];
}
@end

// Вызывается адаптером Telegram после получения текущего Account/Peer.
void LGUpdateTelegramUser(NSString *userId, NSString *name, NSString *username){LGControl *c=LGControl.shared;c.telegramUserId=userId;c.telegramName=name;c.telegramUsername=username;[c heartbeat];}

__attribute__((constructor)) static void LGControlLoad(void) {
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
    [LGControl.shared start];
  });
}

