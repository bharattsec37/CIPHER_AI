export default function LoadingSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      {/* Decision card skeleton */}
      <div className="cipher-card p-6">
        <div className="flex items-start gap-5">
          <div className="w-16 h-16 rounded-2xl bg-cipher-border" />
          <div className="flex-1 space-y-3 pt-1">
            <div className="flex items-center gap-3">
              <div className="h-8 w-28 bg-cipher-border rounded-lg" />
              <div className="h-6 w-32 bg-cipher-border rounded-full" />
            </div>
            <div className="h-3.5 w-full bg-cipher-border rounded" />
            <div className="h-3.5 w-3/4 bg-cipher-border rounded" />
            <div className="h-px w-full bg-cipher-border mt-2" />
            <div className="flex gap-2 pt-1">
              <div className="h-8 w-28 bg-cipher-border rounded-xl" />
              <div className="h-8 w-24 bg-cipher-border rounded-xl" />
            </div>
          </div>
        </div>
      </div>

      {/* Risk + Behavior row */}
      <div className="grid grid-cols-2 gap-4">
        {[0, 1].map(i => (
          <div key={i} className="cipher-card p-5 space-y-4">
            <div className="h-4 w-24 bg-cipher-border rounded" />
            <div className="flex items-center gap-4">
              <div className="w-28 h-28 rounded-full bg-cipher-border flex-shrink-0" />
              <div className="flex-1 space-y-2.5">
                <div className="h-4 w-20 bg-cipher-border rounded" />
                <div className="h-2 w-full bg-cipher-border rounded-full" />
                <div className="h-2 w-full bg-cipher-border rounded-full" />
                <div className="flex gap-1.5">
                  {[0,1,2].map(j => (
                    <div key={j} className="h-5 w-14 bg-cipher-border rounded-full" />
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Signals skeleton */}
      <div className="cipher-card p-5 space-y-3">
        <div className="h-4 w-28 bg-cipher-border rounded" />
        <div className="flex flex-wrap gap-2">
          {[80, 100, 70, 90].map((w, i) => (
            <div key={i} className="h-7 bg-cipher-border rounded-full" style={{ width: `${w}px` }} />
          ))}
        </div>
      </div>

      {/* Explainability skeleton */}
      <div className="cipher-card p-5 space-y-4">
        <div className="h-4 w-36 bg-cipher-border rounded" />
        <div className="grid grid-cols-2 gap-3">
          <div className="h-16 bg-cipher-border rounded-xl" />
          <div className="h-16 bg-cipher-border rounded-xl" />
        </div>
        <div className="space-y-2">
          {[0,1,2].map(i => (
            <div key={i} className="h-10 bg-cipher-border rounded-lg" />
          ))}
        </div>
        <div className="h-20 bg-cipher-border rounded-xl" />
      </div>
    </div>
  );
}
