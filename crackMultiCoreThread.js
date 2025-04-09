import { createRequire } from 'module'
import { Worker, isMainThread, parentPort, workerData } from 'worker_threads'
import bcrypt from 'bcryptjs'
import fs from 'fs'

const require = createRequire(import.meta.url)
const numCPUs = require('os').cpus().length

let mcupws = fs.readFileSync('mcupws_filtered.json', 'utf-8')
mcupws = JSON.parse(mcupws)

let hashes = fs.readFileSync('hashes.txt', 'utf-8')
hashes = hashes.split('\n').flatMap(line => {
  const regex = /"(.*?)"/g
  const matches = line.match(regex)
  return matches ? matches.map(match => match.replace(/"/g, '')) : []
})

const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

function* pwsOfLenN(n) {
  if (n === 1) yield* alphabet
  else {
    for (let ch of alphabet) {
      for (let pw of pwsOfLenN(n - 1)) {
        yield `${ch}${pw}`
      }
    }
  }
}

function* interweavePws() {
  yield ''
  yield* mcupws.slice(0, 100)
  yield* pwsOfLenN(1)
  yield* mcupws.slice(100, 1000)
  yield* pwsOfLenN(2)
  yield* mcupws.slice(1000, mcupws.length)
  yield* pwsOfLenN(3)
}

function crackPasswordsInRange(start, end) {
  let foundAny = false

  for (let i = start; i < end; i++) {
    const hash = hashes[i]
    let hashFound = false

    for (let pw of [...interweavePws()]) {
      if (bcrypt.compareSync(pw, hash)) {
        hashFound = true
        if (pw === '') {
          fs.appendFileSync('hashes.answers.txt', `${hash} ''\n`)
        } else {
          fs.appendFileSync('hashes.answers.txt', `${hash} ${pw}\n`)
        }
        break
      }
    }

    if (hashFound) {
      foundAny = true
    }
  }

  return foundAny
}

if (isMainThread) {
  let crackedPws = 0
  const label = 'Tracking the Cracking'

  console.time(label)

  const workers = [];
  const chunkSize = Math.ceil(hashes.length / numCPUs)

  for (let i = 0; i < numCPUs; i++) {
    const start = i * chunkSize
    const end = (i + 1) * chunkSize > hashes.length ? hashes.length : (i + 1) * chunkSize
    const worker = new Worker(new URL(import.meta.url), { workerData: { start, end } })
    workers.push(worker)

    worker.on('message', (message) => {
      if (message === 'found') {
        crackedPws++
        if (crackedPws === hashes.length) {
          console.timeEnd(label)
          workers.forEach(worker => worker.terminate())
        }
      }
    })
  }
} else {
  const { start, end } = workerData;
  const found = crackPasswordsInRange(start, end)
  if (found) {
    parentPort.postMessage('found')
  }
}
