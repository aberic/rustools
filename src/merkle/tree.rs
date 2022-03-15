/*
 * Copyright (c) 2020. Aberic - All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::sync::{Arc, RwLock};

use crate::errors::{Errs, Results};
use crate::merkle::child::NodeChild;
use crate::merkle::node::Node;

/// 默克尔树
///
/// 默克尔树在ge中的定义如下：
///
/// 无法凭空创建一棵默克尔树，即默克尔树的存在条件是必须拥有叶子结点
///
/// 创建默克尔树的唯一方法是传入一个叶子结点开始
///
/// 默克尔树的hash传递是非计算必要的，即通过左右叶子结点计算上层hash值时，如果右叶子结点为空，那么上层hash值直接继承左叶子节点hash值
///
/// 默克尔树的叶子结点永远不会是根结点
///
/// 默克尔树最小层数为2，如果仅存在一个叶子结点，那么是一棵两层树，且为树的左叶子结点
///
/// 如果是空树，则遵循上述要求，创建两层树，并赋值底层左叶子结点
///
/// 默克尔树每层都能容纳固定数量的叶子结点，且总数量等于2^(level-1)
///
/// 设总数量为N，层数为L，当默克尔树层数为2时，即L=2，N=2^(2-1)=2，表示当前两层默克尔树能容纳2个叶子结点；同理当L=5，N=2^(5-1)=16
///
/// 默克尔树允许存在孤儿叶子结点以及孤儿中间结点，但不会存在孤儿根节点，根节点永远都会有两个子节点，且允许右叶子结点为空
///
/// 默克尔树的左子树永远是满载的，即新增结点时总会向右子树进行寻道，并且是递归寻道，寻道最底层，即L=1时，优先放置在左叶子节点
///
/// 当新增结点发现当前默克尔树已经满载，则整棵树除了根结点外整体下沉并成为根结点的左子树，新增结点从根结点右子树中寻找空叶子结点位
pub struct Tree {
    /// 默克尔树当前层高
    level: u32,
    /// 默克尔树当前根节点
    root: Arc<RwLock<Node>>,
}

/// 新建默克尔树
fn new_string(hash: String) -> Tree {
    let node = Node::new(
        hash.clone(),
        1,
        Some(Arc::new(RwLock::new(NodeChild::new(hash)))),
    );
    return Tree {
        level: 2,
        root: Arc::new(RwLock::new(node)),
    };
}

pub trait TreeMake<Hash> {
    /// 新建默克尔树
    fn new(hash: Hash) -> Tree;
    /// 新增结点
    fn add(&mut self, hash: Hash) -> Results<()>;
}

impl TreeMake<String> for Tree {
    fn new(hash: String) -> Tree {
        new_string(hash)
    }

    fn add(&mut self, hash: String) -> Results<()> {
        self.add_string(hash)
    }
}

impl TreeMake<&str> for Tree {
    fn new(hash: &str) -> Tree {
        new_string(hash.to_string())
    }

    fn add(&mut self, hash: &str) -> Results<()> {
        self.add_string(hash.to_string())
    }
}

impl Tree {
    pub fn level(&self) -> u32 {
        self.level
    }

    pub fn root(&self) -> Arc<RwLock<Node>> {
        self.root.clone()
    }

    pub fn hash(&self) -> String {
        self.root.read().unwrap().hash()
    }

    /// 新增结点
    pub fn add(&mut self, hash: &str) -> Results<()> {
        self.add_string(hash.to_string())
    }

    /// 新增结点
    fn add_string(&mut self, hash: String) -> Results<()> {
        // 当前默克尔树可容纳叶子结点总数
        let root_count = 2_u32.pow(self.level - 1);
        let mut root = self.root.write().unwrap();
        // 如果默克尔树可容纳叶子结点总数大于当前叶子结点数，则说明当前树未满载，允许新结点右插入
        if root_count > root.count() {
            // 新结点右插入
            root.add(self.level, hash)
        // 如果默克尔树可容纳叶子结点总数等于当前叶子结点数，则说明当前树满载，默克尔树除了根结点外整体下沉并成为根结点的左子树，新增结点从根结点右子树中寻找空叶子结点位
        } else if root_count == root.count() {
            match root.child() {
                // 子结点如果存在，则继续判断子结点信息
                Some(nc) => {
                    let mut child_new = NodeChild::new("".to_string());
                    // 变更根结点左子树
                    child_new.modify_left(root.hash(), root.count(), Some(nc));
                    // 变更根结点右子树
                    child_new.none_right();
                    root.modify_child(Some(Arc::new(RwLock::new(child_new))));
                }
                None => {
                    return Err(Errs::str(
                        "merkle data invalid, root child do not exist, try to rebuild!",
                    ));
                }
            }
            // 默克尔树层高+1
            self.level += 1;
            root.add(self.level, hash)
        // 如果默克尔树可容纳叶子结点总数小于当前叶子结点数，则说明当前树异常，需要重建
        } else {
            Err(Errs::str("merkle data invalid, try to rebuild!"))
        }
    }
}
